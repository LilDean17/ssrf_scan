package burp;

import java.awt.*;
import java.awt.event.*;
import java.io.*;
import java.net.*;
import java.nio.charset.StandardCharsets;
import java.util.*;
import java.util.List;
import java.util.concurrent.*;
import java.util.regex.*;
import javax.swing.*;
import javax.swing.table.AbstractTableModel;

public class BurpExtender implements IBurpExtender, ITab, IHttpListener, IMessageEditorController {

    private static final String SCANNER_HEADER = "X-SSRF-Scanner";

    // ceye.io OOB platform
    private static final String CEYE_API_HOST = "api.ceye.io";
    private static final int CEYE_API_PORT = 80;
    private static final String CEYE_API_SCHEME = "http";
    private static final String CEYE_RECORD_PATH_PREFIX = "/v1/records";

    private IBurpExtenderCallbacks callbacks;
    private IExtensionHelpers helpers;

    private JPanel mainPanel;
    private JTable ssrfTable;
    private SSRFTableModel tableModel;

    private JTextField eyesDomainField;
    private JTextField eyesTokenField;

    private JButton startButton;
    private JButton stopButton;
    private JButton clearButton;

    private volatile boolean isRunning = true;
    private ExecutorService executor;
    private ScheduledExecutorService siteMapPoller;

    private final List<SSRFResult> results = new ArrayList<>();
    private final Set<String> testedParams = ConcurrentHashMap.newKeySet();

    private IMessageEditor requestViewer;
    private IMessageEditor responseViewer;
    private IHttpRequestResponse currentlyDisplayedItem;

    private JPanel messageViewerPanel;
    private JSplitPane mainVerticalSplitPane;

    private final Object LOG_LOCK = new Object();

    @Override
    public void registerExtenderCallbacks(IBurpExtenderCallbacks callbacks) {
        this.callbacks = callbacks;
        this.helpers = callbacks.getHelpers();

        callbacks.setExtensionName("SSRF Scanner - Ceye");
        callbacks.registerHttpListener(this);

        SwingUtilities.invokeLater(() -> {
            mainPanel = new JPanel(new BorderLayout());
            mainPanel.add(createMainSplitPane(), BorderLayout.CENTER);

            callbacks.addSuiteTab(BurpExtender.this);

            // 加载即启动：初始化线程池，让插件进入 started 状态
            executor = Executors.newFixedThreadPool(10);

            // 兜底监听：周期性轮询 Burp SiteMap，覆盖 Proxy 视图过滤掉但 Burp 内部仍记录的请求
            // 解决图片代理类 SSRF (?url=http://...) 被 PNG/JPG 过滤器隐藏导致漏报的问题
            siteMapPoller = Executors.newSingleThreadScheduledExecutor();
            siteMapPoller.scheduleAtFixedRate(this::pollSiteMap, 10, 10, TimeUnit.SECONDS);

            logInfo("SSRF Scanner (ceye.io) Loaded - Auto Started (SiteMap polling every 10s)");
        });
    }

    // =========================
    // UI
    // =========================

    private JSplitPane createMainSplitPane() {
        JPanel topPanel = new JPanel(new BorderLayout());

        JPanel leftPanel = new JPanel(new BorderLayout());
        leftPanel.setBorder(BorderFactory.createTitledBorder("SSRF Results"));

        tableModel = new SSRFTableModel();
        ssrfTable = new JTable(tableModel);
        ssrfTable.setAutoCreateRowSorter(true);

        ssrfTable.getColumnModel().getColumn(0).setPreferredWidth(50);
        ssrfTable.getColumnModel().getColumn(1).setPreferredWidth(150);
        ssrfTable.getColumnModel().getColumn(2).setPreferredWidth(400);
        ssrfTable.getColumnModel().getColumn(3).setPreferredWidth(120);
        ssrfTable.getColumnModel().getColumn(4).setPreferredWidth(200);

        ssrfTable.addMouseListener(new MouseAdapter() {
            @Override
            public void mouseClicked(MouseEvent e) {
                int row = ssrfTable.rowAtPoint(e.getPoint());
                if (row >= 0) {
                    int modelRow = ssrfTable.convertRowIndexToModel(row);
                    SSRFResult result = tableModel.getResult(modelRow);
                    showRequestDetails(result);
                }
            }
        });

        leftPanel.add(new JScrollPane(ssrfTable), BorderLayout.CENTER);

        JPanel rightPanel = new JPanel(new BorderLayout());
        rightPanel.add(createSettingsPanel(), BorderLayout.NORTH);

        JSplitPane topSplit = new JSplitPane(
                JSplitPane.HORIZONTAL_SPLIT,
                leftPanel,
                rightPanel
        );
        topSplit.setResizeWeight(0.75);

        topPanel.add(topSplit, BorderLayout.CENTER);

        messageViewerPanel = createMessageViewerPanel();
        messageViewerPanel.setVisible(false);

        mainVerticalSplitPane = new JSplitPane(
                JSplitPane.VERTICAL_SPLIT,
                topPanel,
                messageViewerPanel
        );
        mainVerticalSplitPane.setResizeWeight(0.7);

        return mainVerticalSplitPane;
    }

    private JPanel createSettingsPanel() {
        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Ceye.io Config"));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(5, 5, 5, 5);
        gbc.anchor = GridBagConstraints.WEST;
        gbc.fill = GridBagConstraints.HORIZONTAL;
        gbc.weightx = 1.0;

        int row = 0;

        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0;
        panel.add(new JLabel("Ceye Domain:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        eyesDomainField = new JTextField("<your-ceye-domain>.ceye.io", 20);
        panel.add(eyesDomainField, gbc);

        row++;

        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.weightx = 0;
        panel.add(new JLabel("Ceye Token:"), gbc);

        gbc.gridx = 1;
        gbc.weightx = 1.0;
        eyesTokenField = new JTextField("<your-ceye-token>", 20);
        panel.add(eyesTokenField, gbc);

        row++;

        gbc.gridx = 0;
        gbc.gridy = row;
        gbc.gridwidth = 2;
        gbc.weightx = 1.0;

        JPanel buttonPanel = new JPanel(new FlowLayout(FlowLayout.LEFT));

        startButton = new JButton("Start");
        stopButton = new JButton("Stop");
        clearButton = new JButton("Clear");

        // 插件加载后默认 started 状态：Start 不可用，Stop 可用
        startButton.setEnabled(false);
        stopButton.setEnabled(true);

        startButton.addActionListener(e -> startScanner());
        stopButton.addActionListener(e -> stopScanner());
        clearButton.addActionListener(e -> clearResults());

        buttonPanel.add(startButton);
        buttonPanel.add(stopButton);
        buttonPanel.add(clearButton);

        panel.add(buttonPanel, gbc);

        return panel;
    }

    private JPanel createMessageViewerPanel() {
        JPanel panel = new JPanel(new BorderLayout());
        panel.setBorder(BorderFactory.createTitledBorder("Request / Response"));

        requestViewer = callbacks.createMessageEditor(this, false);
        responseViewer = callbacks.createMessageEditor(this, false);

        JSplitPane splitPane = new JSplitPane(
                JSplitPane.HORIZONTAL_SPLIT,
                requestViewer.getComponent(),
                responseViewer.getComponent()
        );
        splitPane.setResizeWeight(0.5);

        panel.add(splitPane, BorderLayout.CENTER);

        return panel;
    }

    // =========================
    // Scanner Control
    // =========================

    private void startScanner() {
        isRunning = true;
        startButton.setEnabled(false);
        stopButton.setEnabled(true);

        if (executor == null || executor.isShutdown()) {
            executor = Executors.newFixedThreadPool(10);
        }

        if (siteMapPoller == null || siteMapPoller.isShutdown()) {
            siteMapPoller = Executors.newSingleThreadScheduledExecutor();
            siteMapPoller.scheduleAtFixedRate(this::pollSiteMap, 10, 10, TimeUnit.SECONDS);
        }

        logInfo("Scanner Started");
    }

    private void stopScanner() {
        isRunning = false;
        startButton.setEnabled(true);
        stopButton.setEnabled(false);

        if (executor != null) {
            executor.shutdownNow();
            executor = null;
        }

        if (siteMapPoller != null) {
            siteMapPoller.shutdownNow();
            siteMapPoller = null;
        }

        logInfo("Scanner Stopped");
    }

    private void clearResults() {
        synchronized (results) {
            results.clear();
        }
        testedParams.clear();
        tableModel.fireTableDataChanged();
        logInfo("Results Cleared");
    }

    // =========================
    // HTTP Listener
    // =========================

    @Override
    public void processHttpMessage(int toolFlag, boolean messageIsRequest, IHttpRequestResponse messageInfo) {
        if (!isRunning || !messageIsRequest) {
            return;
        }

        // 替代 Proxy 的被动监听：IHttpListener + TOOL_PROXY 已经能拿到所有流经 Burp 的代理流量
        // Burp 自身若启用了"丢弃超出范围的请求"/"按 MIME 过滤"等规则，被丢掉的包 listener 也收不到
        if (executor == null || executor.isShutdown()) {
            return;
        }

        IRequestInfo requestInfo;
        try {
            requestInfo = helpers.analyzeRequest(messageInfo);
        } catch (Exception e) {
            return;
        }

        if (requestInfo.getUrl() == null) {
            return;
        }

        String host = requestInfo.getUrl().getHost();
        if (host != null && host.toLowerCase(Locale.ROOT).endsWith("ceye.io")) {
            return;
        }

        if (isScannerRequest(messageInfo)) {
            return;
        }

        executor.submit(() -> {
            try {
                scanForSSRF(messageInfo);
            } catch (Exception e) {
                logError("Scan Error: " + e.getMessage());
            }
        });
    }

    private boolean isScannerRequest(IHttpRequestResponse messageInfo) {
        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);
            for (String header : requestInfo.getHeaders()) {
                if (header != null && header.toLowerCase(Locale.ROOT).startsWith(SCANNER_HEADER.toLowerCase(Locale.ROOT) + ":")) {
                    return true;
                }
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    // =========================
    // SiteMap Polling (Logger 兜底)
    // =========================

    /**
     * 周期性扫描 Burp SiteMap，覆盖被 Proxy 视图过滤（按 MIME/扩展名）但仍被 Burp 内部记录的请求。
     * 解决图片代理 / 静态资源型 SSRF（?url=http://...）被过滤器隐藏后漏报的问题。
     */
    private void pollSiteMap() {
        if (!isRunning || executor == null || executor.isShutdown()) {
            return;
        }

        IHttpRequestResponse[] entries;
        try {
            // urlPrefix 传 null 表示不过滤前缀，返回全量 SiteMap（涵盖 Proxy/Logger 记录的所有请求）
            entries = callbacks.getSiteMap(null);
        } catch (Exception e) {
            logError("SiteMap Poll Error: " + e.getMessage());
            return;
        }

        if (entries == null || entries.length == 0) {
            return;
        }

        int submitted = 0;
        for (IHttpRequestResponse entry : entries) {
            if (entry == null) {
                continue;
            }
            try {
                byte[] requestBytes = entry.getRequest();
                if (requestBytes == null) {
                    continue;
                }

                IRequestInfo info = helpers.analyzeRequest(entry);
                if (info.getUrl() == null) {
                    continue;
                }

                String host = info.getUrl().getHost();
                if (host != null && host.toLowerCase(Locale.ROOT).endsWith("ceye.io")) {
                    continue;
                }

                if (isScannerRequest(entry)) {
                    continue;
                }

                if (!hasUntestedParams(info)) {
                    continue;
                }

                final IHttpRequestResponse captured = entry;
                executor.submit(() -> {
                    try {
                        scanForSSRF(captured);
                    } catch (Exception e) {
                        logError("SiteMap Scan Error: " + e.getMessage());
                    }
                });
                submitted++;
            } catch (Exception ignored) {
                // 单条解析失败不影响整体
            }
        }

        if (submitted > 0) {
            logDebug("SiteMap poll submitted " + submitted + " new entries for scanning");
        }
    }

    private boolean hasUntestedParams(IRequestInfo info) {
        try {
            if (info.getUrl() == null) {
                return false;
            }
            String host = info.getUrl().getHost();
            String path = info.getUrl().getPath();
            if (host == null) {
                return false;
            }

            List<IParameter> params = info.getParameters();
            for (IParameter param : params) {
                int t = param.getType();
                if (t != IParameter.PARAM_URL && t != IParameter.PARAM_BODY) {
                    continue;
                }
                String paramKey = host + "|" + path + "|" + param.getName();
                if (!testedParams.contains(paramKey)) {
                    return true;
                }
            }
        } catch (Exception ignored) {
        }
        return false;
    }

    // =========================
    // Scan Logic
    // =========================

    private void scanForSSRF(IHttpRequestResponse messageInfo) {
        IRequestInfo requestInfo = helpers.analyzeRequest(messageInfo);

        if (requestInfo.getUrl() == null) {
            return;
        }

        String host = requestInfo.getUrl().getHost();
        String path = requestInfo.getUrl().getPath();
        List<IParameter> parameters = requestInfo.getParameters();

        for (IParameter param : parameters) {
            if (param.getType() == IParameter.PARAM_JSON) {
                continue;
            }

            if (param.getType() != IParameter.PARAM_URL &&
                    param.getType() != IParameter.PARAM_BODY) {
                continue;
            }

            String value = param.getValue();
            String paramKey = host + "|" + path + "|" + param.getName();

            if (testedParams.contains(paramKey)) {
                continue;
            }

            testedParams.add(paramKey);

            if (isURL(value)) {
                logDebug("URL Detected -> " + param.getName());
                testURLSSRF(messageInfo, param);
            } else {
                String target = extractIPorDomain(value);
                if (target != null) {
                    logDebug("IP/Domain Detected -> " + target);
                    testReplaceSSRF(messageInfo, param, value, target);
                }
            }
        }

        scanComplexJson(messageInfo, requestInfo, host, path);
    }

    // =========================
    // Complex JSON Support
    // =========================

    private void scanComplexJson(IHttpRequestResponse messageInfo, IRequestInfo requestInfo, String host, String path) {
        try {
            byte[] requestBytes = messageInfo.getRequest();
            int bodyOffset = requestInfo.getBodyOffset();

            if (bodyOffset < 0 || bodyOffset >= requestBytes.length) {
                return;
            }

            String body = new String(requestBytes, bodyOffset, requestBytes.length - bodyOffset, StandardCharsets.UTF_8).trim();
            if (!looksLikeJson(body)) {
                return;
            }

            JsonParser parser = new JsonParser(body);
            JsonNode root = parser.parse();

            List<JsonTarget> targets = new ArrayList<>();
            collectJsonTargets(root, "", targets);

            for (JsonTarget target : targets) {
                String paramKey = host + "|" + path + "|" + target.jsonPath;

                if (testedParams.contains(paramKey)) {
                    continue;
                }

                testedParams.add(paramKey);

                if (target.isUrl) {
                    logDebug("JSON URL Detected -> " + target.jsonPath + " = " + target.originalValue);
                    testJsonSSRF(messageInfo, target, requestInfo);
                } else if (target.extractedTarget != null) {
                    logDebug("JSON IP/Domain Detected -> " + target.jsonPath + " = " + target.originalValue + " | Extracted: " + target.extractedTarget);
                    testJsonReplaceSSRF(messageInfo, target, requestInfo);
                }
            }
        } catch (Exception e) {
            logError("JSON Scan Error: " + e.getMessage());
        }
    }

    private boolean looksLikeJson(String body) {
        if (body == null) {
            return false;
        }
        String t = body.trim();
        return t.startsWith("{") || t.startsWith("[");
    }

    private void collectJsonTargets(JsonNode node, String path, List<JsonTarget> targets) {
        if (node == null) {
            return;
        }

        switch (node.type) {
            case OBJECT:
                for (Map.Entry<String, JsonNode> entry : node.objectChildren.entrySet()) {
                    String childPath = path.isEmpty() ? entry.getKey() : path + "." + entry.getKey();
                    collectJsonTargets(entry.getValue(), childPath, targets);
                }
                break;

            case ARRAY:
                for (int i = 0; i < node.arrayChildren.size(); i++) {
                    String childPath = path + "[" + i + "]";
                    collectJsonTargets(node.arrayChildren.get(i), childPath, targets);
                }
                break;

            case STRING:
                String value = node.stringValue;
                if (value == null) {
                    return;
                }

                if (isURL(value)) {
                    targets.add(JsonTarget.forUrl(path, node, value));
                } else {
                    String extracted = extractIPorDomain(value);
                    if (extracted != null) {
                        targets.add(JsonTarget.forDomainOrIp(path, node, value, extracted));
                    }
                }
                break;

            default:
                break;
        }
    }

    private void testJsonSSRF(IHttpRequestResponse originalMessage, JsonTarget target, IRequestInfo requestInfo) {
        try {
            String random = generateRandomString(8);
            String eyesDomain = eyesDomainField.getText().trim();
            String payload = "http://" + random + "." + eyesDomain;

            String newJsonValue = payload;
            String newBody = replaceJsonStringValue(requestInfo, originalMessage.getRequest(), target.node, newJsonValue);

            byte[] newRequest = buildRequestWithNewBody(originalMessage.getRequest(), newBody);
            newRequest = addScannerHeader(newRequest);

            IHttpRequestResponse response = callbacks.makeHttpRequest(
                    originalMessage.getHttpService(),
                    newRequest
            );

            Thread.sleep(2000);

            if (checkCeyeHit(random)) {
                addResult(
                        originalMessage,
                        response,
                        target.jsonPath,
                        payload
                );
                logInfo("SSRF FOUND -> " + payload);
            }

        } catch (Exception e) {
            logError(e.getMessage());
        }
    }

    private void testJsonReplaceSSRF(IHttpRequestResponse originalMessage, JsonTarget target, IRequestInfo requestInfo) {
        try {
            String random = generateRandomString(8);
            String eyesDomain = eyesDomainField.getText().trim();

            // JSON 内部如果是 IP / 域名，替换成随机前缀 + ceye 域名，不加协议
            String payload = random + "." + eyesDomain;
            String newValue = target.originalValue.replace(target.extractedTarget, payload);

            String newBody = replaceJsonStringValue(requestInfo, originalMessage.getRequest(), target.node, newValue);

            byte[] newRequest = buildRequestWithNewBody(originalMessage.getRequest(), newBody);
            newRequest = addScannerHeader(newRequest);

            IHttpRequestResponse response = callbacks.makeHttpRequest(
                    originalMessage.getHttpService(),
                    newRequest
            );

            Thread.sleep(2000);

            if (checkCeyeHit(random)) {
                addResult(
                        originalMessage,
                        response,
                        target.jsonPath,
                        payload
                );
                logInfo("SSRF FOUND -> " + payload);
            }

        } catch (Exception e) {
            logError(e.getMessage());
        }
    }

    private String replaceJsonStringValue(IRequestInfo requestInfo, byte[] originalRequest, JsonNode node, String newValue) {
        String body = new String(originalRequest, requestInfo.getBodyOffset(), originalRequest.length - requestInfo.getBodyOffset(), StandardCharsets.UTF_8);
        String escaped = escapeJsonString(newValue);

        int relativeStart = node.start;
        int relativeEnd = node.end;

        String before = body.substring(0, relativeStart);
        String after = body.substring(relativeEnd);

        return before + "\"" + escaped + "\"" + after;
    }

    private byte[] buildRequestWithNewBody(byte[] originalRequest, String newBody) {
        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(originalRequest);
            List<String> headers = new ArrayList<>(requestInfo.getHeaders());

            headers = replaceOrAddHeader(headers, "Content-Length", String.valueOf(newBody.getBytes(StandardCharsets.UTF_8).length));
            headers = ensureScannerHeader(headers);

            return helpers.buildHttpMessage(headers, newBody.getBytes(StandardCharsets.UTF_8));
        } catch (Exception e) {
            logError("Error building JSON request: " + e.getMessage());
            return originalRequest;
        }
    }

    private List<String> ensureScannerHeader(List<String> headers) {
        List<String> newHeaders = new ArrayList<>();
        boolean found = false;

        for (String h : headers) {
            if (h == null) {
                continue;
            }
            if (h.toLowerCase(Locale.ROOT).startsWith(SCANNER_HEADER.toLowerCase(Locale.ROOT) + ":")) {
                if (!found) {
                    newHeaders.add(SCANNER_HEADER + ": 1");
                    found = true;
                }
            } else {
                newHeaders.add(h);
            }
        }

        if (!found) {
            newHeaders.add(SCANNER_HEADER + ": 1");
        }

        return newHeaders;
    }

    private List<String> replaceOrAddHeader(List<String> headers, String name, String value) {
        List<String> newHeaders = new ArrayList<>();
        boolean replaced = false;
        String prefix = name.toLowerCase(Locale.ROOT) + ":";

        for (String h : headers) {
            if (h == null) {
                continue;
            }
            if (h.toLowerCase(Locale.ROOT).startsWith(prefix)) {
                if (!replaced) {
                    newHeaders.add(name + ": " + value);
                    replaced = true;
                }
            } else {
                newHeaders.add(h);
            }
        }

        if (!replaced) {
            newHeaders.add(name + ": " + value);
        }

        return newHeaders;
    }

    // =========================
    // URL SSRF
    // =========================

    private void testURLSSRF(IHttpRequestResponse originalMessage, IParameter param) {
        try {
            String random = generateRandomString(8);
            String eyesDomain = eyesDomainField.getText().trim();
            String payload = "http://" + random + "." + eyesDomain;

            byte[] newRequest = helpers.updateParameter(
                    originalMessage.getRequest(),
                    helpers.buildParameter(param.getName(), payload, param.getType())
            );

            newRequest = addScannerHeader(newRequest);

            IHttpRequestResponse response = callbacks.makeHttpRequest(
                    originalMessage.getHttpService(),
                    newRequest
            );

            Thread.sleep(2000);

            if (checkCeyeHit(random)) {
                addResult(originalMessage, response, param.getName(), payload);
                logInfo("SSRF FOUND -> " + payload);
            }

        } catch (Exception e) {
            logError(e.getMessage());
        }
    }

    // =========================
    // Replace Domain/IP SSRF
    // 不添加协议
    // =========================

    private void testReplaceSSRF(
            IHttpRequestResponse originalMessage,
            IParameter param,
            String originalValue,
            String extractedTarget
    ) {
        try {
            String random = generateRandomString(8);
            String eyesDomain = eyesDomainField.getText().trim();

            // 核心需求：不加 http://
            String payload = random + "." + eyesDomain;

            String newValue = originalValue.replace(extractedTarget, payload);

            byte[] newRequest = helpers.updateParameter(
                    originalMessage.getRequest(),
                    helpers.buildParameter(param.getName(), newValue, param.getType())
            );

            newRequest = addScannerHeader(newRequest);

            IHttpRequestResponse response = callbacks.makeHttpRequest(
                    originalMessage.getHttpService(),
                    newRequest
            );

            Thread.sleep(2000);

            if (checkCeyeHit(random)) {
                addResult(originalMessage, response, param.getName(), payload);
                logInfo("SSRF FOUND -> " + payload);
            }

        } catch (Exception e) {
            logError(e.getMessage());
        }
    }

    // =========================
    // Ceye.io Check
    // =========================

    /**
     * 通过 ceye.io API 查询指定前缀的 DNS/HTTP 记录是否存在
     * API: http://api.ceye.io/v1/records?token={token}&type={dns|http}
     * 响应 JSON 中 data[] 的 name 字段形如 "{prefix}.{domain}"
     */
    private boolean checkCeyeHit(String prefix) {
        try {
            String token = eyesTokenField.getText().trim();
            String domain = eyesDomainField.getText().trim();

            String needle = prefix + "." + domain;

            if (checkCeyeApi("dns", token, needle)) {
                return true;
            }

            if (checkCeyeApi("http", token, needle)) {
                return true;
            }

        } catch (Exception e) {
            logError("Ceye Check Error: " + e.getMessage());
        }

        return false;
    }

    private boolean checkCeyeApi(String type, String token, String needle) {
        try {
            String path = CEYE_RECORD_PATH_PREFIX + "?token=" + urlEncode(token) + "&type=" + type;
            String urlString = CEYE_API_SCHEME + "://" + CEYE_API_HOST + path;

            logDebug("Ceye API Request: " + urlString);

            IHttpService service = helpers.buildHttpService(CEYE_API_HOST, CEYE_API_PORT, CEYE_API_SCHEME);

            String requestStr =
                    "GET " + path + " HTTP/1.1\r\n" +
                    "Host: " + CEYE_API_HOST + "\r\n" +
                    "Connection: close\r\n" +
                    "User-Agent: Mozilla/5.0 (Burp SSRF Scanner)\r\n" +
                    "\r\n";

            byte[] requestBytes = requestStr.getBytes(StandardCharsets.UTF_8);

            logDebug("Ceye Raw Request:\n" + escapeForLog(requestStr));

            IHttpRequestResponse rr = callbacks.makeHttpRequest(service, requestBytes);

            byte[] responseBytes = rr.getResponse();
            if (responseBytes == null) {
                logDebug("Ceye API Response is null");
                return false;
            }

            String responseText = helpers.bytesToString(responseBytes);
            String body = extractBody(responseText);

            logDebug("Ceye API Response Body: " + escapeForLog(body));

            if (body == null) {
                return false;
            }

            // ceye API 响应中 data[].name 形如 "prefix.ceye.domain"
            // 在响应体中直接匹配 needle（大小写不敏感）
            return body.toLowerCase(Locale.ROOT).contains(needle.toLowerCase(Locale.ROOT));

        } catch (Exception e) {
            logError("Ceye API error (" + type + "): " + e.getMessage());
            return false;
        }
    }

    // =========================
    // Burp helpers
    // =========================

    private byte[] addScannerHeader(byte[] requestBytes) {
        try {
            IRequestInfo requestInfo = helpers.analyzeRequest(requestBytes);
            List<String> headers = new ArrayList<>(requestInfo.getHeaders());

            boolean hasScannerHeader = false;
            for (String header : headers) {
                if (header != null && header.toLowerCase(Locale.ROOT).startsWith(SCANNER_HEADER.toLowerCase(Locale.ROOT) + ":")) {
                    hasScannerHeader = true;
                    break;
                }
            }

            if (!hasScannerHeader) {
                headers.add(SCANNER_HEADER + ": 1");
            }

            byte[] body = Arrays.copyOfRange(requestBytes, requestInfo.getBodyOffset(), requestBytes.length);
            return helpers.buildHttpMessage(headers, body);
        } catch (Exception e) {
            logError("Error adding scanner header: " + e.getMessage());
            return requestBytes;
        }
    }

    private String extractBody(String fullResponse) {
        if (fullResponse == null) {
            return null;
        }
        int idx = fullResponse.indexOf("\r\n\r\n");
        if (idx >= 0 && idx + 4 <= fullResponse.length()) {
            return fullResponse.substring(idx + 4);
        }
        return fullResponse;
    }

    private String urlEncode(String s) throws UnsupportedEncodingException {
        return URLEncoder.encode(s, "UTF-8");
    }

    // =========================
    // Utils
    // =========================

    private boolean isURL(String value) {
        try {
            URL url = new URL(value);
            return url.getProtocol().matches("https?");
        } catch (Exception e) {
            return false;
        }
    }

    private String extractIPorDomain(String value) {
        String ipv4Pattern = "\\b(?:(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\.){3}(?:25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\\b";
        Matcher ipv4Matcher = Pattern.compile(ipv4Pattern).matcher(value);
        if (ipv4Matcher.find()) {
            return ipv4Matcher.group();
        }

        String domainPattern = "\\b(?:[a-zA-Z0-9-]+\\.)+[a-zA-Z]{2,}\\b";
        Matcher domainMatcher = Pattern.compile(domainPattern).matcher(value);
        if (domainMatcher.find()) {
            return domainMatcher.group();
        }

        return null;
    }

    private String generateRandomString(int len) {
        String chars = "abcdefghijklmnopqrstuvwxyz0123456789";
        Random random = new Random();
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < len; i++) {
            sb.append(chars.charAt(random.nextInt(chars.length())));
        }
        return sb.toString();
    }

    private String escapeJsonString(String s) {
        if (s == null) {
            return "";
        }
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < s.length(); i++) {
            char c = s.charAt(i);
            switch (c) {
                case '"': sb.append("\\\""); break;
                case '\\': sb.append("\\\\"); break;
                case '\b': sb.append("\\b"); break;
                case '\f': sb.append("\\f"); break;
                case '\n': sb.append("\\n"); break;
                case '\r': sb.append("\\r"); break;
                case '\t': sb.append("\\t"); break;
                default:
                    if (c < 0x20) {
                        sb.append(String.format("\\u%04x", (int) c));
                    } else {
                        sb.append(c);
                    }
            }
        }
        return sb.toString();
    }

    // =========================
    // Result
    // =========================

    private void addResult(
            IHttpRequestResponse requestResponse,
            IHttpRequestResponse response,
            String parameter,
            String payload
    ) {
        SSRFResult result = new SSRFResult(
                requestResponse.getHttpService().getHost(),
                requestResponse.getHttpService().getPort(),
                requestResponse.getHttpService().getProtocol(),
                helpers.analyzeRequest(requestResponse).getUrl().toString(),
                parameter,
                payload,
                requestResponse.getRequest(),
                response.getResponse()
        );

        synchronized (results) {
            results.add(result);
        }

        SwingUtilities.invokeLater(() -> tableModel.fireTableDataChanged());
    }

    // =========================
    // Request Viewer
    // =========================

    private void showRequestDetails(SSRFResult result) {
        currentlyDisplayedItem = new IHttpRequestResponse() {
            @Override
            public byte[] getRequest() {
                return result.getRequest();
            }

            @Override
            public byte[] getResponse() {
                return result.getResponse();
            }

            @Override
            public IHttpService getHttpService() {
                return helpers.buildHttpService(
                        result.getHost(),
                        result.getPort(),
                        result.getProtocol()
                );
            }

            @Override public void setRequest(byte[] message) {}
            @Override public void setResponse(byte[] message) {}
            @Override public String getComment() { return null; }
            @Override public void setComment(String comment) {}
            @Override public String getHighlight() { return null; }
            @Override public void setHighlight(String color) {}
            @Override public void setHttpService(IHttpService httpService) {}
        };

        requestViewer.setMessage(result.getRequest(), true);
        responseViewer.setMessage(result.getResponse(), false);

        if (!messageViewerPanel.isVisible()) {
            messageViewerPanel.setVisible(true);
            mainVerticalSplitPane.setDividerLocation(0.7);
        }
    }

    // =========================
    // ITab
    // =========================

    @Override
    public String getTabCaption() {
        return "SSRF Scanner";
    }

    @Override
    public Component getUiComponent() {
        return mainPanel;
    }

    // =========================
    // IMessageEditorController
    // =========================

    @Override
    public IHttpService getHttpService() {
        return currentlyDisplayedItem == null ? null : currentlyDisplayedItem.getHttpService();
    }

    @Override
    public byte[] getRequest() {
        return currentlyDisplayedItem == null ? null : currentlyDisplayedItem.getRequest();
    }

    @Override
    public byte[] getResponse() {
        return currentlyDisplayedItem == null ? null : currentlyDisplayedItem.getResponse();
    }

    // =========================
    // Table
    // =========================

    private class SSRFTableModel extends AbstractTableModel {
        private final String[] columns = {"#", "Host", "URL", "Parameter", "Payload"};

        @Override
        public int getRowCount() {
            synchronized (results) {
                return results.size();
            }
        }

        @Override
        public int getColumnCount() {
            return columns.length;
        }

        @Override
        public String getColumnName(int column) {
            return columns[column];
        }

        @Override
        public Object getValueAt(int rowIndex, int columnIndex) {
            synchronized (results) {
                SSRFResult r = results.get(rowIndex);
                switch (columnIndex) {
                    case 0:
                        return rowIndex + 1;
                    case 1:
                        return r.getHost();
                    case 2:
                        return r.getUrl();
                    case 3:
                        return r.getParameterName();
                    case 4:
                        return r.getPayload();
                    default:
                        return "";
                }
            }
        }

        public SSRFResult getResult(int row) {
            synchronized (results) {
                return results.get(row);
            }
        }
    }

    // =========================
    // Result Class
    // =========================

    private class SSRFResult {
        private final String host;
        private final int port;
        private final String protocol;
        private final String url;
        private final String parameterName;
        private final String payload;
        private final byte[] request;
        private final byte[] response;

        public SSRFResult(String host, int port, String protocol, String url,
                          String parameterName, String payload,
                          byte[] request, byte[] response) {
            this.host = host;
            this.port = port;
            this.protocol = protocol;
            this.url = url;
            this.parameterName = parameterName;
            this.payload = payload;
            this.request = request;
            this.response = response;
        }

        public String getHost() { return host; }
        public int getPort() { return port; }
        public String getProtocol() { return protocol; }
        public String getUrl() { return url; }
        public String getParameterName() { return parameterName; }
        public String getPayload() { return payload; }
        public byte[] getRequest() { return request; }
        public byte[] getResponse() { return response; }
    }

    // =========================
    // JSON Parser Support
    // =========================

    private static class JsonTarget {
        final String jsonPath;
        final JsonNode node;
        final String originalValue;
        final boolean isUrl;
        final String extractedTarget;

        private JsonTarget(String jsonPath, JsonNode node, String originalValue, boolean isUrl, String extractedTarget) {
            this.jsonPath = jsonPath;
            this.node = node;
            this.originalValue = originalValue;
            this.isUrl = isUrl;
            this.extractedTarget = extractedTarget;
        }

        static JsonTarget forUrl(String jsonPath, JsonNode node, String originalValue) {
            return new JsonTarget(jsonPath, node, originalValue, true, null);
        }

        static JsonTarget forDomainOrIp(String jsonPath, JsonNode node, String originalValue, String extractedTarget) {
            return new JsonTarget(jsonPath, node, originalValue, false, extractedTarget);
        }
    }

    private static class JsonNode {
        enum Type { OBJECT, ARRAY, STRING, NUMBER, BOOLEAN, NULL }

        final Type type;
        final int start;
        final int end;
        final String stringValue;
        final Map<String, JsonNode> objectChildren;
        final List<JsonNode> arrayChildren;

        JsonNode(Type type, int start, int end, String stringValue, Map<String, JsonNode> objectChildren, List<JsonNode> arrayChildren) {
            this.type = type;
            this.start = start;
            this.end = end;
            this.stringValue = stringValue;
            this.objectChildren = objectChildren;
            this.arrayChildren = arrayChildren;
        }
    }

    private static class JsonParser {
        private final String text;
        private int pos = 0;

        JsonParser(String text) {
            this.text = text;
        }

        JsonNode parse() {
            skipWhitespace();
            JsonNode node = parseValue();
            skipWhitespace();
            if (pos != text.length()) {
                throw new IllegalArgumentException("Extra JSON data at position " + pos);
            }
            return node;
        }

        private JsonNode parseValue() {
            skipWhitespace();
            if (pos >= text.length()) {
                throw new IllegalArgumentException("Unexpected end of JSON");
            }

            char c = text.charAt(pos);
            switch (c) {
                case '{':
                    return parseObject();
                case '[':
                    return parseArray();
                case '"':
                    return parseString();
                case 't':
                case 'f':
                    return parseBoolean();
                case 'n':
                    return parseNull();
                default:
                    if (c == '-' || Character.isDigit(c)) {
                        return parseNumber();
                    }
                    throw new IllegalArgumentException("Invalid JSON value at position " + pos);
            }
        }

        private JsonNode parseObject() {
            int start = pos;
            pos++;

            Map<String, JsonNode> children = new LinkedHashMap<>();
            skipWhitespace();

            if (pos < text.length() && text.charAt(pos) == '}') {
                pos++;
                return new JsonNode(JsonNode.Type.OBJECT, start, pos, null, children, null);
            }

            while (true) {
                skipWhitespace();
                JsonNode keyNode = parseString();
                String key = keyNode.stringValue;

                skipWhitespace();
                expect(':');

                JsonNode valueNode = parseValue();
                children.put(key, valueNode);

                skipWhitespace();
                if (pos >= text.length()) {
                    throw new IllegalArgumentException("Unterminated object");
                }

                char c = text.charAt(pos);
                if (c == ',') {
                    pos++;
                    continue;
                } else if (c == '}') {
                    pos++;
                    break;
                } else {
                    throw new IllegalArgumentException("Expected ',' or '}' at position " + pos);
                }
            }

            return new JsonNode(JsonNode.Type.OBJECT, start, pos, null, children, null);
        }

        private JsonNode parseArray() {
            int start = pos;
            pos++;

            List<JsonNode> children = new ArrayList<>();
            skipWhitespace();

            if (pos < text.length() && text.charAt(pos) == ']') {
                pos++;
                return new JsonNode(JsonNode.Type.ARRAY, start, pos, null, null, children);
            }

            while (true) {
                JsonNode value = parseValue();
                children.add(value);

                skipWhitespace();
                if (pos >= text.length()) {
                    throw new IllegalArgumentException("Unterminated array");
                }

                char c = text.charAt(pos);
                if (c == ',') {
                    pos++;
                    continue;
                } else if (c == ']') {
                    pos++;
                    break;
                } else {
                    throw new IllegalArgumentException("Expected ',' or ']' at position " + pos);
                }
            }

            return new JsonNode(JsonNode.Type.ARRAY, start, pos, null, null, children);
        }

        private JsonNode parseString() {
            int start = pos;
            expect('"');

            StringBuilder sb = new StringBuilder();

            while (pos < text.length()) {
                char c = text.charAt(pos++);

                if (c == '"') {
                    return new JsonNode(JsonNode.Type.STRING, start, pos, sb.toString(), null, null);
                }

                if (c == '\\') {
                    if (pos >= text.length()) {
                        throw new IllegalArgumentException("Invalid escape sequence at end of string");
                    }
                    char esc = text.charAt(pos++);
                    switch (esc) {
                        case '"': sb.append('"'); break;
                        case '\\': sb.append('\\'); break;
                        case '/': sb.append('/'); break;
                        case 'b': sb.append('\b'); break;
                        case 'f': sb.append('\f'); break;
                        case 'n': sb.append('\n'); break;
                        case 'r': sb.append('\r'); break;
                        case 't': sb.append('\t'); break;
                        case 'u':
                            if (pos + 4 > text.length()) {
                                throw new IllegalArgumentException("Invalid unicode escape at position " + pos);
                            }
                            String hex = text.substring(pos, pos + 4);
                            try {
                                sb.append((char) Integer.parseInt(hex, 16));
                            } catch (NumberFormatException e) {
                                throw new IllegalArgumentException("Invalid unicode escape at position " + pos);
                            }
                            pos += 4;
                            break;
                        default:
                            throw new IllegalArgumentException("Invalid escape character '\\" + esc + "' at position " + pos);
                    }
                } else {
                    sb.append(c);
                }
            }

            throw new IllegalArgumentException("Unterminated string starting at " + start);
        }

        private JsonNode parseBoolean() {
            int start = pos;
            if (text.startsWith("true", pos)) {
                pos += 4;
                return new JsonNode(JsonNode.Type.BOOLEAN, start, pos, "true", null, null);
            }
            if (text.startsWith("false", pos)) {
                pos += 5;
                return new JsonNode(JsonNode.Type.BOOLEAN, start, pos, "false", null, null);
            }
            throw new IllegalArgumentException("Invalid boolean at position " + pos);
        }

        private JsonNode parseNull() {
            int start = pos;
            if (text.startsWith("null", pos)) {
                pos += 4;
                return new JsonNode(JsonNode.Type.NULL, start, pos, "null", null, null);
            }
            throw new IllegalArgumentException("Invalid null at position " + pos);
        }

        private JsonNode parseNumber() {
            int start = pos;
            if (text.charAt(pos) == '-') {
                pos++;
            }
            while (pos < text.length() && Character.isDigit(text.charAt(pos))) {
                pos++;
            }
            if (pos < text.length() && text.charAt(pos) == '.') {
                pos++;
                while (pos < text.length() && Character.isDigit(text.charAt(pos))) {
                    pos++;
                }
            }
            if (pos < text.length() && (text.charAt(pos) == 'e' || text.charAt(pos) == 'E')) {
                pos++;
                if (pos < text.length() && (text.charAt(pos) == '+' || text.charAt(pos) == '-')) {
                    pos++;
                }
                while (pos < text.length() && Character.isDigit(text.charAt(pos))) {
                    pos++;
                }
            }

            String num = text.substring(start, pos);
            return new JsonNode(JsonNode.Type.NUMBER, start, pos, num, null, null);
        }

        private void skipWhitespace() {
            while (pos < text.length()) {
                char c = text.charAt(pos);
                if (c == ' ' || c == '\t' || c == '\r' || c == '\n') {
                    pos++;
                } else {
                    break;
                }
            }
        }

        private void expect(char expected) {
            skipWhitespace();
            if (pos >= text.length() || text.charAt(pos) != expected) {
                throw new IllegalArgumentException("Expected '" + expected + "' at position " + pos);
            }
            pos++;
        }
    }

    // =========================
    // Logging
    // =========================

    private synchronized void logInfo(String msg) {
        callbacks.printOutput("[INFO] " + msg);
    }

    private synchronized void logDebug(String msg) {
        callbacks.printOutput("[DEBUG] " + msg);
    }

    private synchronized void logError(String msg) {
        callbacks.printError("[ERROR] " + msg);
    }

    private String escapeForLog(String s) {
        if (s == null) {
            return "null";
        }
        return s.replace("\r", "\\r").replace("\n", "\\n");
    }
}
