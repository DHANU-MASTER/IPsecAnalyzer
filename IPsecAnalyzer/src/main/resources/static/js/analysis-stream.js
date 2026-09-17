/*
 * Live analysis streaming for the dashboard.
 *
 * Loaded after the inline dashboard script, so it can replace analyzePcap()
 * with a version that streams progress over STOMP (SockJS) and renders the
 * final result when it arrives. If the live channel is unavailable the
 * original synchronous endpoint is used instead.
 */
(function () {
    'use strict';

    var client = null;
    var subscribed = false;

    function byId(id) {
        return document.getElementById(id);
    }

    function token() {
        return localStorage.getItem('authToken');
    }

    function currentUsername() {
        try {
            return JSON.parse(atob(token().split('.')[1])).username || 'user';
        } catch (e) {
            return 'user';
        }
    }

    /* Escape server-provided strings before injecting them into HTML. */
    window.esc = function (value) {
        if (value === null || value === undefined) {
            return '';
        }
        return String(value)
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    };

    function setProgress(percent, status) {
        var wrap = byId('progressWrap');
        var bar = byId('progressBar');
        var label = byId('progressStatus');
        if (wrap) {
            wrap.style.display = 'block';
        }
        if (bar) {
            var pct = Math.max(0, Math.min(100, percent || 0));
            bar.style.width = pct + '%';
            bar.textContent = pct + '%';
            bar.setAttribute('aria-valuenow', String(pct));
        }
        if (label && status) {
            label.textContent = status;
        }
    }

    function hideProgress() {
        var wrap = byId('progressWrap');
        if (wrap) {
            wrap.style.display = 'none';
        }
    }

    function busy(state) {
        var spinner = byId('spinner');
        var button = byId('analyzeBtn');
        if (spinner) {
            spinner.style.display = state ? 'block' : 'none';
        }
        if (button) {
            button.disabled = state;
        }
    }

    function showResults(data) {
        if (typeof window.displayResults === 'function') {
            window.displayResults(data);
        }
        if (data && data.configuration) {
            var source = byId('configSource');
            if (source) {
                source.textContent = 'Configuration source: ' + data.configuration.source
                    + ' \u2014 ' + data.configuration.note;
            }
        }
        var results = byId('results');
        if (results) {
            results.classList.add('show');
            results.scrollIntoView({ behavior: 'smooth', block: 'start' });
        }
    }

    function handleUnauthorized() {
        alert('Session expired. Please login again.');
        localStorage.removeItem('authToken');
        window.location.href = '/login';
    }

    /* Connect to the STOMP broker and subscribe to this user's topics. */
    window.connectStream = function () {
        if (client || !window.StompJs || !window.SockJS || !token()) {
            return;
        }
        client = new window.StompJs.Client({
            webSocketFactory: function () {
                return new window.SockJS('/ws-analysis');
            },
            reconnectDelay: 5000,
            heartbeatIncoming: 10000,
            heartbeatOutgoing: 10000
        });

        client.onConnect = function () {
            var topic = '/topic/analysis/' + currentUsername();

            client.subscribe(topic, function (message) {
                var payload;
                try {
                    payload = JSON.parse(message.body);
                } catch (e) {
                    return;
                }
                if (payload.type === 'error') {
                    alert('Analysis failed: ' + (payload.error || 'unknown error'));
                    busy(false);
                    setProgress(100, 'Analysis failed');
                    return;
                }
                setProgress(payload.percent, payload.status);
            });

            client.subscribe(topic + '/result', function (message) {
                var data;
                try {
                    data = JSON.parse(message.body);
                } catch (e) {
                    return;
                }
                showResults(data);
                setProgress(100, 'Analysis complete');
                busy(false);
                setTimeout(hideProgress, 1500);
            });

            subscribed = true;
        };

        client.onStompError = function () {
            subscribed = false;
        };

        client.activate();
    };

    /* Synchronous fallback used when the live channel is not available. */
    async function analyzeDirect(file) {
        var formData = new FormData();
        formData.append('file', file);

        var response = await fetch('/api/analyze/pcap', {
            method: 'POST',
            headers: { 'Authorization': 'Bearer ' + token() },
            body: formData
        });

        if (response.status === 401) {
            handleUnauthorized();
            return;
        }

        var text = await response.text();
        var data;
        try {
            data = JSON.parse(text);
        } catch (e) {
            alert('Server response: ' + (text || response.statusText || 'Analysis complete'));
            return;
        }

        if (!response.ok) {
            alert('Error: ' + (data.message || data.error || 'Analysis failed'));
            return;
        }

        showResults(data);
    }

    /* Replaces the inline analyzePcap(): streams progress, falls back if needed. */
    window.analyzePcap = async function () {
        var input = byId('pcapFile');
        var file = input && input.files ? input.files[0] : null;

        if (!file) {
            alert('Please select a .pcap file');
            return;
        }
        if (!token()) {
            window.location.href = '/login';
            return;
        }

        busy(true);
        setProgress(5, 'Uploading capture...');

        try {
            if (!client || !subscribed) {
                await analyzeDirect(file);
                busy(false);
                hideProgress();
                return;
            }

            var formData = new FormData();
            formData.append('file', file);

            var response = await fetch('/api/analyze/pcap-streaming', {
                method: 'POST',
                headers: { 'Authorization': 'Bearer ' + token() },
                body: formData
            });

            if (response.status === 401) {
                handleUnauthorized();
                return;
            }

            if (response.status !== 202) {
                // Streaming endpoint unavailable - fall back to the synchronous call
                await analyzeDirect(file);
                busy(false);
                hideProgress();
                return;
            }

            setProgress(10, 'Analysis started...');
            // Completion is handled by the /result subscription
        } catch (error) {
            alert('Error: ' + error.message);
            busy(false);
            hideProgress();
        }
    };
})();
