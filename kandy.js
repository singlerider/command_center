// Kandy.js
// Site: http://kandy.io
// Version: 2.3.0
// Copyright 2015 Genband
// ----------------------
// UMD module definition as described by https://github.com/umdjs/umd
(function (root, factory) {
    if (typeof define === 'function' && define.amd) {
        // AMD. Register as an anonymous module.
        define(factory);
    } else {
        // Browser globals
        root.kandy = root.KandyAPI = factory.apply({});
    }
 }(this, function () {
    'use strict';

    var kandyVersion = '2.3.0';

    // UMD module definition as described by https://github.com/umdjs/umd
(function (root, factory) {
    if (typeof define === 'function' && define.amd) {
        // AMD. Register as an anonymous module.
        define(factory);
    } else {
        // Browser globals
        root.fcs = factory();
    }
 }(this, function () {

// DO NOT UPDATE THIS DEFINITION
// IT IS ONLY USED FOR REMOVING TEST
// SPECIFIC REFERENCES FROM API.
var __testonly__;
var GlobalBroadcaster = function() {
    var MAX_PRIORITY = 10, MIN_PRIORITY = 1, topics = {}, subUid = -1;

    function unsubscribeFromTopic(token) {
        var m, i, j;
        for (m in topics) {
            if (topics[m] && topics.hasOwnProperty(m)) {
                for (i = 0, j = topics[m].length; i < j; i++) {
                    if (topics[m][i].token === token) {
                        topics[m].splice(i, 1);
                        return token;
                    }
                }
            }
        }
        return false;
    }

    function subscribeToTopic(topic, func, priority, temporary) {
        var token, prio = MAX_PRIORITY, temp = false;

        if (typeof topic !== 'string') {
            throw new Error("First parameter must be a string topic name.");
        }

        if (typeof func !== 'function') {
            throw new Error("Second parameter must be a function.");
        }

        if (typeof priority !== 'undefined') {
            if (typeof priority !== 'number') {
                throw new Error("Priority must be a number.");
            }
            else {
                if (priority > MAX_PRIORITY ||
                        priority < MIN_PRIORITY) {
                    throw new Error("Priority must be between 1-10.");
                }
                else {
                    prio = priority;
                }
            }
        }

        if (temporary === true) {
            temp = temporary;
        }

        if (!topics[topic]) {
            topics[topic] = [];
        }

        token = (++subUid).toString();
        topics[topic].push({
            token: token,
            prio: prio,
            func: func,
            temp: temp
        });

        topics[topic].sort(function(a, b) {
            return parseFloat(b.prio) - parseFloat(a.prio);
        });

        return token;
    }

    function publishTopic(topic, args) {
        var subscribers, len, _args, _topic;

        if (arguments.length === 0) {
            throw new Error("First parameter must be a string topic name.");
        }

        _args = Array.prototype.slice.call(arguments);
        _topic = _args.shift();

        subscribers = topics[_topic];
        len = subscribers ? subscribers.length : 0;
        while (len--) {
            subscribers[len].func.apply(null, _args);
            if (subscribers[len].temp) {
                unsubscribeFromTopic(subscribers[len].token);
            }
        }
    }

    /*
     *
     * Publish events of interest
     * with a specific topic name and arguments
     * such as the data to pass along
     *
     * @param {string} topic - Topic name.
     * @param {...*} [args] - arguments.
     *
     * @returns {undefined}
     */
    this.publish = publishTopic;

    /*
     *
     * Subscribe to events of interest
     * with a specific topic name and a
     * callback function, to be executed
     * when the topic/event is observed.
     * Default priority 10.
     * Priority must be between 1-10.
     * Functions with lower priority
     * will be executed first.
     *
     * @param {string} topic - Topic name.
     * @param {type} func - function to be executed when the topic/event is observed
     * @param {number} [priority] - function with higher priority will be executed first
     * @param {boolean} [temporary] - if set to true, subscriber will unsubcribe automatically after first execution.
     *
     * @returns {string} token - reference to subscription
     */
    this.subscribe = subscribeToTopic;

    /*
     *
     * Unsubscribe from a specific
     * topic, based on a tokenized reference
     * to the subscription
     *
     * @param {string} token - reference to subscription
     *
     * @returns {false|string} - returns token if successfull,
     * otherwise returns false.
     */
    this.unsubscribe = unsubscribeFromTopic;
};

var globalBroadcaster = new GlobalBroadcaster();
if (__testonly__) { __testonly__.GlobalBroadcaster = GlobalBroadcaster; }
var CONSTANTS = {
    "WEBRTC": {
        "PLUGIN_ID": "fcsPlugin",
        "MEDIA_STATE": {
            NOT_FOUND: "notfound",
            SEND_RECEIVE: "sendrecv",
            SEND_ONLY: "sendonly",
            RECEIVE_ONLY: "recvonly",
            INACTIVE: "inactive"
        },
        "PLUGIN_MODE": {
            WEBRTC: "webrtc", // 2.1 Enabler Plugin
            LEGACY: "legacy", // 1.2 Disabler Plugin
            LEGACYH264: "legacyh264", // 1.3 Disabler Plugin with H264
            AUTO: "auto"          // Native For Chrome Browser and 2.1 Enabler Plugin for other Browsers
        },
        "RTC_SIGNALING_STATE": {
            STABLE: "stable",
            HAVE_LOCAL_OFFER: "have-local-offer",
            HAVE_REMOTE_OFFER: "have-remote-offer",
            HAVE_LOCAL_PRANSWER: "have-local-pranswer",
            HAVE_REMOTE_PRANSWER: "have-remote-pranswer",
            CLOSED: "closed"
        },
        "RTC_SDP_TYPE": {
            "OFFER": "offer",
            "ANSWER": "answer",
            "PRANSWER": "pranswer"
        }
    },
    "STRING": {
        "NEW_LINE": "\n",
        "CARRIAGE_RETURN": "\r",
        "VIDEO" : "video",
        "AUDIO" : "audio"
    },
    "SDP" : {
        "A_LINE" : "a=",
        "M_LINE" : "m=",
        "CRYPTO" : "crypto",
        "FINGERPRINT" : "fingerprint",
        "ICE_UFRAG": "ice-ufrag:",
        "ICE_PWD": "ice-pwd:",
        "NACK": "nack",
        "NACKPLI": "nack pli"
    },
    "HTTP_METHOD" : {
        "GET" : "GET",
        "POST" : "POST",
        "PUT" : "PUT",
        "DELETE" : "DELETE",
        "OPTIONS" : "OPTIONS"
    },
    "WEBSOCKET": {
        "PROTOCOL": {
            "SECURE": "wss",
            "NONSECURE": "ws"
        },
        "DEFAULT_PORT": "8581",
        "STATUS": {
            "OPENED": 1,
            "ALREADY_OPENED": 2,
            "CREATE_ERROR": 3,
            "CONNECTION_ERROR": 4,
            "NOT_FOUND": 5,
            "CONNECTION_CLOSED": 6
        }
    },
    "COLLABORATION": {
        "GUEST_SUFFIX": "-guest"
    },
    "EVENT": {
        "XHR_REQUEST_NOT_INITIALIZED" : "XHR_REQUEST_NOT_INITIALIZED",
        "DEVICE_SUBSCRIPTION_STARTED": "DEVICE_SUBSCRIPTION_STARTED",
        "DEVICE_SUBSCRIPTION_ENDED": "DEVICE_SUBSCRIPTION_ENDED",
        "CONNECTION_REESTABLISHED": "CONNECTION_REESTABLISHED",
        "CONNECTION_LOST": "CONNECTION_LOST",
        "TOKEN_AUTH_STARTED": "TOKEN_AUTH_STARTED",
        "BASIC_AUTH_STARTED": "BASIC_AUTH_STARTED",
        "TOKEN_NOT_FOUND": "TOKEN_NOT_FOUND",
        "SESSION_EXPIRED": "SESSION_EXPIRED",
        "TURN_CREDENTIALS_ESTABLISHED": "TURN_CREDENTIALS_ESTABLISHED",
        "NOTIFICATION_CHANNEL_LOST": "NOTIFICATION_CHANNEL_LOST"
    }
};
if (__testonly__) { __testonly__.CONSTANTS = CONSTANTS; }
var JQrestful = function() {

    var ajaxSetuped = false,
        DEFAULT_LONGPOLLING_TOLERANCE = 30000,
        DEFAULT_AJAX_TIMEOUT = 40000,
        XHR_READY_STATE = {
            REQUEST_NOT_INITIALIZED: 0,
            REQUEST_DONE: 4
        };

    function getLogger() {
        return logManager.getLogger("jQrestful");
    }

    function composeAjaxRequestResponseLog(context, xhr, errorThrown, data) {
        var responseLog = context;
        if (data) {
            responseLog.data = data;
        }
        if (errorThrown) {
            responseLog.errorThrown = errorThrown;
        }
        if (xhr) {
            responseLog.status = xhr.status;
            responseLog.statusText = xhr.statusText;
            responseLog.responseText = xhr.responseText;
            responseLog.readyState = xhr.readyState;
        }
        return responseLog;
    }

    function parseError(x, e) {
        var returnResult, statusCode;
        getLogger().error("parseError:'" + e + "' Status:'" + x.status + "' ResponseText:'" + x.responseText + "'");

        if (x.responseText && x.responseText.search("statusCode") !== -1) {
            if (JSON.parse(x.responseText).subscribeResponse !== undefined) {
                statusCode = JSON.parse(x.responseText).subscribeResponse.statusCode;
            } else if (JSON.parse(x.responseText).authorizationResponse !== undefined) {
                statusCode = JSON.parse(x.responseText).authorizationResponse.statusCode;
            }
        }

        statusCode = statusCode ? statusCode : x.status;

        switch (statusCode) {
            case 401:
                returnResult = fcs.Errors.AUTH;
                break;
            case 403:
                returnResult = fcs.Errors.INCORRECT_LOGIN_PASS;
                break;
            case 19:
                returnResult = fcs.Errors.LOGIN_LIMIT_CLIENT;
                break;
            case 20:
                returnResult = fcs.Errors.LOGIN_LIMIT_TABLET;
                break;
            case 44:
                returnResult = fcs.Errors.FORCE_LOGOUT_ERROR;
                break;
            case 46:
                returnResult = fcs.Errors.TOKEN_NOT_FOUND;
                break;
            case 47:
                returnResult = fcs.Errors.SESSION_EXPIRED;
                break;
            default:
                returnResult = fcs.Errors.NETWORK;
        }
        return returnResult;
    }

    // TODO tolga: remove parseError when all of the responseTypes are added
    function parseErrorStatusCode(x, e, responseType) {
        getLogger().error("parseErrorStatusCode:'" + e + "' Status:'" + x.status + "' ResponseText:'" + x.responseText + "'");

        if (x.responseText && x.responseText.search("statusCode") !== -1 && JSON.parse(x.responseText)[responseType] !== undefined) {

            return JSON.parse(x.responseText)[responseType].statusCode;
        }

        return (x.status === 401 || x.status === 403) ? x.status : 400;
    }


    /**
     * @ignore
     */
    this.call = function(method, callParams, successHandler, errorHandler, successParser, errorParser, responseType, headers) {
        var data,
            timeout = DEFAULT_AJAX_TIMEOUT,
            url = callParams.url,
            resourceString,
            logger = getLogger(),
            xhr,
            queryString,
            finalHeaders,
            headerKey,
            responseLogContext,
            callback,
            handleSuccess,
            handleError,
            isSuccess,
            val;

        if (callParams && callParams.data) {
            data = callParams.data;
        }

        if (fcsConfig.polling) {
            timeout = fcsConfig.polling * 1000;
            if (fcsConfig.longpollingTolerans) {
                timeout = timeout + fcsConfig.longpollingTolerans;
            } else {
                timeout = timeout + DEFAULT_LONGPOLLING_TOLERANCE;
            }
        }

        if (url.split("/rest/version/")[1]) {
            // extracting rest resource from url.
            // ".../rest/version/<ver>/<user/anonymous>/<userName>/restResource/..."
            resourceString = url.split("/rest/version/")[1].split("/")[3];
            if (!resourceString) {
                // rest resource string not found, get last string in the url
                resourceString = url.substring(url.lastIndexOf("/") + 1, url.length);
            }
            // remove "?" if exists
            resourceString = resourceString.split("?")[0];

            if (data) {
                logger.info("Send ajax request: " + resourceString, data);
            } else {
                logger.info("Send ajax request: " + resourceString);
            }
        }

        if (method === 'GET') {
            // Take the data parameters and append them to the URL.
            queryString = utils.param(data);

            if (queryString.length > 0) {
                url = url + '?' + queryString;
            }

            // Remove data so that we don't add it to the body.
            data = null;
        }

        xhr = new XMLHttpRequest();
        xhr.open(method, url, fcs.isAsync());
        xhr.withCredentials = fcsConfig.cors ? true : false;
        xhr.timeout = timeout;

        finalHeaders = {
            // Old implementation used jQuery without changing content type. Doing the same here for
            // backwards compatibility.
            'Content-Type': 'application/x-www-form-urlencoded',

            // JQuery always adds this header by default. Adding here for backwards compatibility.
            'X-Requested-With': 'XMLHttpRequest'
        };

        finalHeaders = utils.extend(finalHeaders, headers);

        // Set the headers.
        for (headerKey in finalHeaders) {
            xhr.setRequestHeader(headerKey, finalHeaders[headerKey]);
        }

        if (typeof data !==  "string") {
            data = JSON.stringify(data);
        }

        xhr.send(data);

        // Used for logging information,
        responseLogContext = {
            type: method,
            url: url,
            dataType: "json",
            async: fcs.isAsync(),
            jsonp: false,
            crossDomain: fcsConfig.cors ? true : false,
            timeout: timeout
        };

        handleSuccess = function(val) {
            if (successParser && typeof successParser === 'function') {
                val = successParser(val);
            }
            if (successHandler && typeof successHandler === 'function') {
                successHandler(val);
            }
        };

        handleError = function (){
            if (errorHandler && typeof errorHandler === 'function') {
                //TODO after unit tests moved to addressbook class, responseType parameter should be removed
                if (responseType === "addressBookResponse") {
                    errorHandler(parseErrorStatusCode(xhr, xhr.statusText, responseType));
                } else {
                    if (errorParser && typeof errorParser === 'function') {
                        errorHandler(errorParser(xhr, xhr.statusText));
                    } else {
                        errorHandler(parseError(xhr, xhr.statusText));
                    }
                }
            } else {
                logger.trace("Error handler is not defined or not a function");
            }
        };

        callback = function() {

            // TODO: Handle abort
            if (xhr.readyState === XHR_READY_STATE.REQUEST_DONE) {

                isSuccess = (xhr.status >= 200 && xhr.status < 300) || xhr.status === 304;

                if (isSuccess) {
                    var val = {};

                    try {
                        // Make sure that the response isn't empty before parsing. Empty is considered
                        // an empty object.
                        if (typeof xhr.responseText === 'string' && xhr.responseText.length) {
                            val = JSON.parse(xhr.responseText);
                        }

                        logger.info("ajax success: " + xhr.status + " " + xhr.statusText,
                            composeAjaxRequestResponseLog(responseLogContext, xhr, undefined, val));

                        handleSuccess(val);
                    } catch(e) {
                        if (e instanceof SyntaxError) {
                            logger.error("Failed to parse json ajax response into object:" + xhr.responseText,
                                composeAjaxRequestResponseLog(responseLogContext, xhr, undefined, val));
                        } else {
                            logger.error("Unknown error:" + xhr.status + " " + xhr.statusText,
                                composeAjaxRequestResponseLog(responseLogContext, xhr, undefined, val));
                        }

                        handleError();
                    }

                } else {

                    // TODO: Error Thrown
                    logger.error("ajax error: " + xhr.status + " " + xhr.statusText,
                        composeAjaxRequestResponseLog(responseLogContext, xhr, xhr.statusText));

                    if (xhr.status === 410) {
                        logger.error("410 Gone received");
                        utils.callFunctionIfExist(fcs.notification.onGoneReceived);
                        return;
                    }

                    if (xhr.status === 0 && xhr.statusText === "abort") {
                        logger.trace("Ajax request aborted internally. not calling failure callback");
                        return;
                    }

                    handleError();
                }
            } else if (xhr.readyState === XHR_READY_STATE.REQUEST_NOT_INITIALIZED) {

                logger.error("ajax error: " + xhr.status + " " + xhr.statusText,
                    composeAjaxRequestResponseLog(responseLogContext, xhr, null));

                if (xhr.status === 0 && xhr.statusText === "abort") {
                    logger.trace("Ajax request aborted internally. not calling failure callback");
                    return;
                }

                globalBroadcaster.publish(CONSTANTS.EVENT.XHR_REQUEST_NOT_INITIALIZED);
                logger.debug("Ajax request cannot be sent, this is a connection problem.");

                handleError();
            }
        };

        // This code is similar to jQuery. It is done like this because the documentations says not
        // to use onreadystatechange if in synchronous mode.
        if (!fcs.isAsync()) {
            // In sync mode, just call the callback
            callback();
        } else if (xhr.readyState === 4) {
            // If the request already completed, just fire the callback asynchronously
            setTimeout(callback);
        } else {
            // Attach the call back
            xhr.onreadystatechange = callback;
        }

        return xhr;
    };
};

var jQueryAdapter = new JQrestful();

var JqrestfullManager = function() {

    var REQUEST_TYPE_PUT = "PUT",
            REQUEST_TYPE_POST = "POST",
            REQUEST_TYPE_GET = "GET",
            REQUEST_TYPE_DELETE = "DELETE",username, password, session;

    function getLogger() {
        return logManager.getLogger("JqrestfullManager");
    }

    function onSubscriptionStarted(data) {
        session = data.session;
    }

    // In order to delete previous session
    function onSubscriptionEnded() {
        session = null;
    }

    function onTokenAuth(data) {
        username = data.username;
    }

    function onBasicAuth(data) {
        username = data.username;
        password = data.password;
    }

    function manipulateHeader(header) {
        if (!header) {
            header = {};
        }
        if (!header.Accept) {
            header.Accept = "application/json";
        }
        if (!header['Content-Type']) {
            header['Content-Type'] = "application/json";
        }
        //Check whether auth or basic auth
        if (session) {
            header['x-session'] = session;
            delete header.Authorization;
        } else {
            if (username && password) {
                header.Authorization = "basic " + window.btoa(username + ":" + password);
            }
            delete header['x-session'];
        }
        return header;
    }

    //TODO: requestTimeout, synchronous parameters should be refactored.
    //TODO: Header parameter should be  the first one. This would be corrected in refactor
    function sendRequest(method, callParams, successHandler, errorHandler, successParser, errorParser, responseType, header) {
        var failureHandler = function(statusCode) {
            if (statusCode === fcs.Errors.TOKEN_NOT_FOUND) {
                globalBroadcaster.publish(CONSTANTS.EVENT.TOKEN_NOT_FOUND);
                session = null;
            } else if (statusCode === fcs.Errors.SESSION_EXPIRED){
                globalBroadcaster.publish(CONSTANTS.EVENT.SESSION_EXPIRED);
                session = null;
            }

            if (errorHandler && typeof errorHandler === 'function') {
                errorHandler(statusCode);
            }
        };
        return jQueryAdapter.call(method, callParams, successHandler, failureHandler, successParser, errorParser, responseType, header);
    }

    function sendPostRequestTokenAuth(callParams, successHandler, errorHandler, successParser, errorParser, responseType, header, token) {
        if (!header) {
            header = {};
        }
        if (!header.Accept) {
            header.Accept = "application/json";
        }
        if (!header['Content-Type']) {
            header['Content-Type'] = "application/json";
        }
        //Check whether auth or basic auth
        if (header['x-session']) {
            delete header['x-session'];
        }
        if (header.Authorization) {
            delete header.Authorization;
        }
        if (!header['x-token']) {
            header['x-token'] = token;
        }
        return sendRequest(REQUEST_TYPE_POST, callParams, successHandler, errorHandler, successParser, errorParser, responseType, header);
    }

    this.call = function(method, callParams, successHandler, errorHandler, successParser, errorParser, responseType, header) {
        header = manipulateHeader(header);

        if (callParams && callParams.data) {
            callParams.data = JSON.stringify(callParams.data);
        }

        return sendRequest(method, callParams, successHandler, errorHandler, successParser, errorParser, responseType, header);
    };

    this.sendPostRequest = function(callParams, successHandler, errorHandler, successParser, errorParser, responseType, header, token) {

        if (callParams && callParams.data) {
            callParams.data = JSON.stringify(callParams.data);
        }

        if (token) {
            return sendPostRequestTokenAuth(callParams, successHandler, errorHandler, successParser, errorParser, responseType, header, token);
        } else {
            header = manipulateHeader(header);
            return sendRequest(REQUEST_TYPE_POST, callParams, successHandler, errorHandler, successParser, errorParser, responseType, header);
        }
    };

    this.sendGetRequest = function(callParams, successHandler, errorHandler, successParser, errorParser, responseType, header) {
        header = manipulateHeader(header);
        return sendRequest(REQUEST_TYPE_GET, callParams, successHandler, errorHandler, successParser, errorParser, responseType, header);
    };

    this.sendDeleteRequest = function(callParams, successHandler, errorHandler, successParser, errorParser, responseType, header) {
        header = manipulateHeader(header);

        if (callParams && callParams.data) {
            callParams.data = JSON.stringify(callParams.data);
        }

        return sendRequest(REQUEST_TYPE_DELETE, callParams, successHandler, errorHandler, successParser, errorParser, responseType, header);
    };

    this.sendPutRequest = function(callParams, successHandler, errorHandler, successParser, errorParser, responseType, header) {
        header = manipulateHeader(header);

        if (callParams && callParams.data) {
            callParams.data = JSON.stringify(callParams.data);
        }

        return sendRequest(REQUEST_TYPE_PUT, callParams, successHandler, errorHandler, successParser, errorParser, responseType, header);
    };

    globalBroadcaster.subscribe(CONSTANTS.EVENT.TOKEN_AUTH_STARTED, onTokenAuth, 9);
    globalBroadcaster.subscribe(CONSTANTS.EVENT.BASIC_AUTH_STARTED, onBasicAuth, 10);
    globalBroadcaster.subscribe(CONSTANTS.EVENT.DEVICE_SUBSCRIPTION_STARTED, onSubscriptionStarted);
    globalBroadcaster.subscribe(CONSTANTS.EVENT.DEVICE_SUBSCRIPTION_ENDED, onSubscriptionEnded);

    if (__testonly__) { this.manipulateHeader = manipulateHeader; }
    if (__testonly__) { this.setSession = function(value) { session = value; }; }
    if (__testonly__) { this.setUsernamePassword = function(user, pass) { username = user; password = pass; }; }
};

var server = new JqrestfullManager();

var fcsConfig = {
    polling: 30
};


var un = null, pw = null, connected = true, tkn = null, tokenRealm = null, kandyUAT = null;

function getDomain() {
    return un.split('@')[1];
}

function getUser() {
    return un;
}

function getUserPassword() {
    return pw;
}

function getUserToken() {
    return tkn;
}

function getRealm() {
    return tokenRealm;
}

function getKandyUAT(){
    return kandyUAT;
}

function getVersion() {
    return "3.0.4";
}

function isConnected() {
    return connected;
}

function setConnected(connectionStatus) {
    connected = connectionStatus === true ? true : false;
}

/**
* @name fcs
* @namespace
*/
var Core = function() {

    var dev = null, pluginVer = null, services = {}, async = true;

    /**
     * This function returns value of async paramater of $.ajax requests
     *
     * @name fcs.isAsync
     * @function
     * @returns {Boolean} true/false
     * @since 3.0.0
     *
     * @example
     * fcs.isAsync();
     */
    this.isAsync = function() {
        return async;
    };

    /**
     * This function sets async option of $.ajax() requests.
     * If It is set to false, ajax requests will be sent synchronously
     * otherwise ajax requests will be sent asynchronously.
     *
     * @name fcs.setAsync
     * @function
     * @param {Boolean} value
     * @return {Boolean} true/false
     * @since 3.0.0
     *
     * @example
     * fcs.setAsync(false);
     */
    this.setAsync = function(value) {
        async = value;
    };

    /**
     * This function returns username of authenticated user in user@domain format.
     *
     * @name fcs.getUser
     * @function
     * @returns {string} Username of current user
     * @since 3.0.0
     *
     * @example
     * fcs.getUser();
     */
    this.getUser = getUser;

     /**
     * This function returns password of authenticated user
     *
     * @name fcs.getUserPassword
     * @function
     * @returns {string} Password of current user
     * @since 3.0.0
     *
     * @example
     * fcs.getUserPassword();
     */
    this.getUserPassword = getUserPassword;

    /**
     * This function returns current domain name of authenticated user
     *
     * @name fcs.getDomain
     * @function
     * @returns {string} Current domain name
     * @since 3.0.0
     *
     * @example
     * fcs.getDomain();
     */
    this.getDomain = getDomain;

    /**
     * This function returns the version of the JSL-API
     *
     * @name fcs.getVersion
     * @function
     * @returns {string} Version of the JSL-API
     * @since 3.0.0
     *
     * @example
     * fcs.getVersion();
     */
    this.getVersion = getVersion;

    /**
     * This fucntion returns current device.
     *
     * @name fcs.getDevice
     * @function
     * @returns {string} Device specified for communicating with the server
     * @since 3.0.0
     *
     * @example
     * fcs.getDevice();
     */
    this.getDevice = function() {
        return dev;
    };

    /**
     * This function sets the user as authentication mode and cancels device authentication (if such exists),
     * as user and device modes are mutually exclusive.
     *
     * @name fcs.setUserAuth
     * @function
     * @param {string} The user to be used for communicating with the server
     * @param {string} The password to be used for communicating with the server
     *
     * @since 3.0.0
     *
     * @example
     * fcs.setUserAuth("Username", "Password");
     */
    this.setUserAuth = function(user, password) {
        un = user;
        pw = password;
        dev = null;
        globalBroadcaster.publish(CONSTANTS.EVENT.BASIC_AUTH_STARTED, {'username' : user, 'password': password});
    };

    /**
     * This function sets the user as token mode authentication and cancels user authentication or/and device authentication (if such exists),
     * token authentication has priority over other authentications
     *
     * @name fcs.setTokenAuth
     * @function
     * @param {string} The user to be used for communicating with the server
     * @param {string} The token to be used for communicating with the server
     *
     * @since 3.0.0
     *
     * @example
     * fcs.setTokenAuth("Username", "Token");
     */
    this.setTokenAuth = function(user, token){
        un = user;
        tkn = token;
        globalBroadcaster.publish(CONSTANTS.EVENT.TOKEN_AUTH_STARTED, {'username' : user, 'token': token});
    };

    /**
     * This function sets the device as authentication mode and cancels user authentication (if such exists),
     * as user and device modes are mutually exclusive.
     *
     * @name fcs.setDeviceAuth
     * @function
     * @since 3.0.0
     * @param {string} deviceID The device to be used for communicating with the server
     *
     * @example
     * fcs.setDeviceAuth("DeviceID");
     */
    this.setDeviceAuth = function(deviceID) {
        dev = deviceID;
        un = null;
    };

    /**
     * This function sets the authentication realm for time limited token authentication.
     *
     * @name fcs.setRealm
     * @function
     * @since 3.0.4
     * @param {string} realm The realm for the time limited token auth
     *
     * @example
     * fcs.setRealm("realmname");
     */
    this.setRealm = function(realm) {
        tokenRealm = realm;
    };

    /**
     * This function sets the authentication UAT for kandy Authentication.
     *
     * @name fcs.setKandyUAT
     * @function
     * @since 3.0.4
     * @param {string} uat The User Access Token
     *
     * @example
     * fcs.setKandyUAT("uat");
     */
    this.setKandyUAT = function(uat) {
        kandyUAT = uat;
    };


    /**
     * List of Authentication Types.
     * @see setDeviceAuth
     * @see setUserAuth
     * @name AuthenticationType
     * @property {number} USER User authentication
     * @property {number} DEVICE Device authentication
     * @readonly
     * @memberOf fcs
     */
    this.AuthenticationType = {
        USER: 1,
        DEVICE: 2
    };

    /**
     * List of Error Types
     *
     * @name fcs.Errors
     * @property {number} NETWORK Network failures
     * @property {number} AUTH Authentication / Authorization failures
     * @property {number} STATE Invalid state
     * @property {number} PRIV Privilege failures
     * @property {number} CONV_SUBS Conversation service subscription failures
     * @property {number} UNKNOWN Unknown failures
     * @property {number} LOGIN_LIMIT Login limit exceeded
     * @property {number} INCORRECT_LOGIN_PASS Incorrect identifier
     * @property {number} INVALID_LOGIN Invalid username
     * @property {number} TOKEN_NOT_FOUND Token provided is not valid
     * @property {number} SESSION_EXPIRED Session generated from token is expired
     * @property {number} VIDEO_SESSION_NOT_AVAILABLE Video Session is not available
     * @property {number} PENDING_REQUEST There is a pending request.
     * @readonly
     * @memberOf fcs
     * @example
     * if (e === fcs.Errors.AUTH)
     * {
     *     console.log("Authentication error occured")
     * }
     */
    this.Errors = {
        NETWORK: 1,
        AUTH: 2,
        STATE: 3,
        PRIV: 4,
        CONV_SUBS: 5,
        UNKNOWN: 9,
        LOGIN_LIMIT_CLIENT: 10,
        INCORRECT_LOGIN_PASS: 11,
        INVALID_LOGIN: 12,
        FORCE_LOGOUT_ERROR : 13, // smartoffice2.0 specific
        LOGIN_LIMIT_TABLET: 14, // smartoffice2.0 specific
        TOKEN_NOT_FOUND: 15,
        SESSION_EXPIRED: 16,
        VIDEO_SESSION_NOT_AVAILABLE: 17,
        PENDING_REQUEST: 18
    };

    /**
     * This function is used to set up JSL library
     *
     * @name fcs.setup
     * @function
     * @param {object} configParams Object containing parameters to be configured
     * @param {fcs.notification.NotificationTypes} [configParams.notificationType] The notification type to be used. Defauts to: LONGPOLLING
     * @param {string} [configParams.restUrl] The URL of REST server http://ip:port. Defaults to an absolute url : /rest
     * @param {string} [configParams.restPort] The port of REST server http://ip:port.
     * @param {string} [configParams.polling] Polling time value in seconds. Default is 30.
     * @param {string} [configParams.expires] Expire time value in miliseconds. Default is 3600.
     * @param {string} [configParams.screenSharingMaxWidth] Defines maximum witdh of screen sharing option.
     * @param {string} [configParams.websocketProtocol] Determines if the websocketProtocol is secure or non-secure. Default is non-secure, which is "ws".
     * @param {string} [configParams.websocketIP] Holds the websocket connection's IP adress.
     * @param {string} [configParams.websocketPort] Holds the websocket connection's port value. By defult, it is 8581.
     * @param {string} [configParams.codecsToRemove] Audio codesc to be removed.
     * @param {string} [configParams.callAuditTimer] Audit time value for calls.
     * @param {string} [configParams.cors] True if Cross-Origin Request Sharing supported.
     * @param {string} [configParams.services] Defines the enabled services for client. Ex: CallControl, IM, call, conversation
     * @param {string} [configParams.sipware] Necessary URL for SIP connection.
     * @param {string} [configParams.protocol] HTTP protocol to be used. Ex: Http, Https
     * @param {string} [configParams.clientIp] The client IP address for SNMP triggers
     * @param {string} [configParams.serverProvidedTurnCredentials] Provide TURN server credentials from server or not.
     * @param {number} [configParams.iceCandidateCollectionTimeoutInterval] When provided (in milliseconds), ice candidate collection assumed to be completed if at least one candidate is received within the interval.
     * @since 3.0.0
     * @example
     *
     * fcs.setup(
     *   {
     *       notificationType: fcs.notification.NotificationTypes.SNMP,
     *       clientIp: 'IP Address',
     *       restUrl: "http://ip:port"
     *   }
     * );
     */
    this.setup = function(configParams) {
        var param;
        for (param in configParams) {
            if (configParams.hasOwnProperty(param)) {
                fcsConfig[param] = configParams[param];
            }
        }
    };

    /**
     * This function sets version of plugin
     *
     * @name fcs.setPluginVersion
     * @function
     * @param {string} version
     * @since 3.0.0
     * @example
     *
     * fcs.setPluginVersion(version);
     */
    this.setPluginVersion = function(version) {
        pluginVer = version;
    };

    /**
     * This function returns version of plugin
     *
     * @name fcs.getPluginVersion
     * @function
     * @returns {String} Version of Current Plugin
     * @since 3.0.0
     * @example
     *
     * fcs.getPluginVersion();
     */
    this.getPluginVersion = function() {
        return pluginVer;
    };

    /**
     * This function returns assigned services of authenticated user.
     *
     * @name fcs.getServices
     * @function
     * @returns {object} The assigned services of authenticated user
     * @since 3.0.0
     * @example
     *
     * fcs.getServices();
     */
    this.getServices = function() {
        return services;
    };

    /**
     * This function assigns determined services to current user
     *
     * @name fcs.setServices
     * @function
     * @param {array} serviceParam The list of assigned services for the user
     * @since 3.0.0
     * @example
     * fcs.setServices(["CallControl", "RestfulClient"]);
     */
    this.setServices = function(serviceParam) {
        var i;
        // for each element in serviceParam array, we create the service with value "true" in "services" object
        if (serviceParam) {
            for (i = 0; i < serviceParam.length; i++) {
                switch (serviceParam[i]) {
                    case "CallDisplay":
                        services.callDisplay = true;
                        break;
                    case "CallDisposition":
                        services.callDisposition = true;
                        break;
                    case "RestfulClient":
                        services.restfulClient = true;
                        break;
                    case "call":
                    case "CallControl":
                        services.callControl = true;
                        break;
                    case "CallMe":
                        services.callMe = true;
                        break;
                    case "Directory":
                        services.directory = true;
                        break;
                    case "ClickToCall":
                        services.clickToCall = true;
                        break;
                    case "Presence":
                        services.presence = true;
                        break;
                    case "AddressBook":
                        services.contacts = true;
                        break;
                    case "CallLog":
                        services.history = true;
                        break;
                    case "Custom":
                        services.custom = true;
                        break;
                    case "IM":
                        services.IM = true;
                        break;
                    case "Route":
                        services.routes = true;
                        break;
                    case "Collaboration":
                        services.collab = true;
                        break;
                    case "conversation":
                    case "Conversation":
                        services.conversation = true;
                        break;
                    default:
                        break;
                }
            }
        }
    };

    /**
     * This function deletes subscription of authenticated user and clear other  user related resources
     *
     * @deprecated use fcs.notification.stop
     * @name fcs.clearResources
     * @function
     * @param {type} done Function to be executed when process done
     * @param {type} clearUserCredentials True if remove the user credentials from local storage
     * @param {type} synchronous
     * @since 3.0.0
     * @example
     * fcs.clearResources();
     *
     */
    this.clearResources = function(done, clearUserCredentials, synchronous) {

        if (synchronous) {
          fcs.setAsync(false);
        }
        fcs.notification.stop(function() {
            //onsuccess
            window.localStorage.removeItem("SubscriptionStamp");
        }, function() {
            //onfailure, can be used in the future
        }, true);
        if (clearUserCredentials) {
            window.localStorage.removeItem("USERNAME");
            window.localStorage.removeItem("PASSWORD");
        }
        if (typeof done === 'function') {
            done();
        }
    };

    this.getUserLocale = function(onSuccess, onFailure) {
        server.sendGetRequest({
                "url":getWAMUrl(1, "/localization", false)
            },
            function (data) {
                utils.callFunctionIfExist(onSuccess, data);
            },
            onFailure
        );
    };


    /**
     * Returns network connectivity status.
     *
     * @name fcs.isConnected
     * @function
     *
     * @returns {Boolean}, true if connection is up otherwise false.
     */
    this.isConnected = isConnected;

}, fcs;

fcs = new Core();

fcs.fcsConfig = fcsConfig;

/**
 *
 * LogManager provides javascript logging framework.<br />
 *
 * <br />The logging level strategy is as follows:<br />
 *
 * <br />DEBUG: Used for development and detailed debugging logs<br />
 * INFO: Messages that provide information about the high level flow<br />
 * through. Contain basic information about the actions being performed<br />
 * by the user and/or the system<br />
 * WARN: Things that shouldn't happen but don't have any immediate effect, and should be flagged<br />
 * ERROR: Errors and Exceptions<br />
 * FATAL: Anything that causes the system to enter into an unstable and unusable state<br />
 *
 *
 * @name logManager
 * @namespace
 * @memberOf fcs
 *
 * @version 3.0.4
 * @since 3.0.0
 *
 */
var LogManager = function() {
    var loggers = {},
            enabled = false,
            Level = {
        OFF: "OFF",
        FATAL: "FATAL",
        ERROR: "ERROR",
        WARN: "WARN",
        INFO: "INFO",
        DEBUG: "DEBUG",
        TRACE: "TRACE",
        ALL: "ALL"
    }, _logHandler = null;

    function getNotificationId() {
        return notificationManager ? notificationManager.getNotificationId() : null;
    }

    /**
     *
     * Log object.
     *
     * @typedef {Object} logObject
     * @readonly
     * @since 3.0.0
     *
     * @property {String}  user - the user registered to fcs library.
     * @property {String}  timestamp - the time stamp of the log.
     * @property {String}  logger - the name of the logger.
     * @property {String}  level - the level of message.
     * @property {?String} notificationId - the notification channnel id used by fcs library.
     * @property {String}  message -  the message string.
     * @property {Object}  args - the arguments.
     *
     */

    /**
     *
     * Log handler function.
     *
     * @typedef {function} logHandler
     * @param {string} loggerName Name of the logger
     * @param {string} level Level of message
     * @param {logObject} logObject Log object
     * @since 3.0.0
     */

    /**
     *
     * Initializes logging using user-provided log handler.
     * @name initLogging
     * @since 3.0.0
     * @function
     * @memberOf fcs.logManager
     *
     * @param {logHandler} logHandler, Function that will receive log entries
     * @param {boolean} enableDebug, Flag defining whether debugging should be enabled or not
     * @returns {undefined}
     *
     * @example
     *
     * function jslLogHandler(loggerName, level, logObject) {
     *     var LOG_LEVEL = fcs.logManager.Level,
     *         msg = logObject.timestamp + " - " + loggerName + " - " + level + " - " + logObject.message;
     *
     *     switch(level) {
     *         case LOG_LEVEL.DEBUG:
     *             window.console.debug(msg, logObject.args);
     *             break;
     *         case LOG_LEVEL.INFO:
     *             window.console.info(msg, logObject.args);
     *             break;
     *         case LOG_LEVEL.ERROR:
     *             window.console.error(msg, logObject.args);
     *             break;
     *             default:
     *             window.console.log(msg, logObject.args);
     *     }
     * }
     *
     * fcs.logManager.initLogging(jslLogHandler, true);
     */
    this.initLogging = function(logHandler, enableDebug) {
        if (!logHandler || typeof logHandler !== 'function') {
            return false;
        }
        _logHandler = logHandler;
        enabled = enableDebug === true ? true : false;
        return true;
    };

    /**
     *
     * Enumerates all possible log levels.
     * @name Level
     * @enum {string}
     * @since 3.0.0
     * @readonly
     * @memberOf fcs.logManager
     * @property {string} [OFF=OFF] string representation of the Off level.
     * @property {string} [FATAL=FATAL]  string representation of the Fatal level.
     * @property {string} [ERROR=ERROR] string representation of the Error level.
     * @property {string} [WARN=WARN] string representation of the Warn level.
     * @property {string} [INFO=INFO] string representation of the Info level.
     * @property {string} [DEBUG=DEBUG] string representation of the Debug level.
     * @property {string} [TRACE=TRACE] string representation of the Trace level.
     * @property {string} [ALL=ALL] string representation of the All level.
     */
    this.Level = Level;

    /**
     * Returns true or false depending on whether logging is enabled.
     *
     * @name isEnabled
     * @function
     * @memberOf fcs.logManager
     *
     * @returns {Boolean}
     * @since 3.0.0
     *
     * @example
     *
     * fcs.logManager.isEnabled();
     *
     */
    this.isEnabled = function() {
        return enabled;
    };

    function Logger(loggerName) {
        var name = loggerName;

        this.getName = function() {
            return name;
        };

        function log(level, message, argument) {
            if (enabled) {
                var logObject = {};

                logObject.user = getUser();
                logObject.timestamp = new Date().getTime();
                logObject.logger = name;
                logObject.level = level;
                logObject.notificationId = getNotificationId();
                logObject.message = message;
                logObject.args = argument;


                if (_logHandler) {
                    try {
                        _logHandler(logObject.logger, logObject.level, logObject);
                    }
                    catch (e) {
                        return undefined;
                    }
                }
            }
            return false;
        }

        this.trace = function trace(msg, argument) {
            return log(Level.TRACE, msg, argument);
        };

        this.debug = function debug(msg, argument) {
            return log(Level.DEBUG, msg, argument);
        };

        this.info = function info(msg, argument) {
            return log(Level.INFO, msg, argument);
        };

        this.warn = function warn(msg, argument) {
            return log(Level.WARN, msg, argument);
        };

        this.error = function error(msg, argument) {
            return log(Level.ERROR, msg, argument);
        };

        this.fatal = function fatal(msg, argument) {
            return log(Level.FATAL, msg, argument);
        };
    }

    this.getLogger = function(loggerName) {
        var logger, _loggerName;
        _loggerName = loggerName ? loggerName.trim().length !== 0 ? loggerName : "Default" : "Default";
        if (loggers[_loggerName]) {
            logger = loggers[_loggerName];
        }
        else {
            logger = new Logger(_loggerName);
            loggers[logger.getName()] = logger;
        }

        return logger;
    };
};

if (__testonly__) { __testonly__.LogManager = LogManager; }
var logManager = new LogManager();
fcs.logManager = logManager;
function getUrl(){
        var url = "";

        if(!fcsConfig.protocol || !fcsConfig.restUrl || !fcsConfig.restPort) {
            return url;
        }
        return url + fcsConfig.protocol + "://" + fcsConfig.restUrl + ":" + fcsConfig.restPort;
    }

    function getWAMUrl(version, url, authNeeded){
        var token = getKandyUAT(), paramExists = (url.indexOf("?") >= 0);
        if(token){
            url += paramExists ? ("&key=" + token) : ("?key=" + token);
        }

        if (authNeeded === false) {
            // Authentcation is not needed.
            return getUrl() + "/rest/version/" + (version?version:"latest") + url;
        } else {
            // Authentcation is needed for the rest request
            if(fcs.notification){
                return getUrl() + "/rest/version/" + (version?version:"latest") + (fcs.notification.isAnonymous() ? "/anonymous/" : "/user/" ) + fcs.getUser() + url;
            }
            else{
                return getUrl() + "/rest/version/" + (version?version:"latest") + "/user/" + fcs.getUser() + url;
            }
        }
    }


    function getSipwareUrl(){
        var url;
        if(fcsConfig.sipware){
            return fcsConfig.sipware + "/WebBroker/connections/";
        }
        return url;
    }

    function getAbsolutePath() {
        var loc = window.location, pathName = loc.pathname.substring(0, loc.pathname.lastIndexOf('/') + 1);
        return loc.href.substring(0, loc.href.length - ((loc.pathname + loc.search + loc.hash).length - pathName.length));
    }

var CookieStorage = function() {
    // Get an object that holds all cookies
    var cookies = (function() {
        var cookies = {},
            all = document.cookie,
            list,
            i = 0,
            cookie, firstEq, name, value;
        if (all === "") {
            return cookies;
        }

        list = all.split("; "); // Split into individual name=value pairs

        for(; i < list.length; i += 1) {
            cookie = list[i];
            firstEq = cookie.indexOf("="); // Find the first = sign
            name = cookie.substring(0, firstEq); // Get cookie name
            value = cookie.substring(firstEq+1); // Get cookie value
            value = decodeURIComponent(value); // Decode the value

            cookies[name] = value;
        }
        return cookies;
    }()),

    // Collect the cookie names in an array
    keys = [],
    key;
    for(key in cookies) {
        if(cookies.hasOwnProperty(key)){
            keys.push(key);
        }

    }
    // Public API
    this.length = keys.length;


    // Return the name of the nth cookie, or null if n is out of range
    this.key = function(n) {
        if (n < 0 || n >= keys.length) {
            return null;
        }

        return keys[n];
    };

    // Return the value of the named cookie, or null.
    this.getItem = function(name) {
        if (arguments.length !== 1) {
            throw new Error("Provide one argument");
        }

        return cookies[name] || null;
    };

    this.setItem = function(key, value) {
        if (arguments.length !== 2) {
           throw new Error("Provide two arguments");
        }

        if (cookies[key] === undefined) { // If no existing cookie with this name
            keys.push(key);
            this.length++;
        }

        cookies[key] = value;

        var cookie = key + "=" + encodeURIComponent(value),
        today = new Date(),
        expiry = new Date(today.getTime() + 30 * 24 * 3600 * 1000);
        // Add cookie attributes to that string

        cookie += "; max-age=" + expiry;


        cookie += "; path=/";

        // Set the cookie through the document.cookie property
        document.cookie = cookie;
    };

    // Remove the specified cookie
    this.removeItem = function(key) {
        if (arguments.length !== 1) {
            throw new Error("Provide one argument");
        }

        var i = 0, max;
        if (cookies[key] === undefined) { // If it doesn't exist, do nothing
            return;
        }

        // Delete the cookie from our internal set of cookies
        delete cookies[key];

        // And remove the key from the array of names, too.
        for(max = keys.length; i < max; i += 1) {
            if (keys[i] === key) { // When we find the one we want
                keys.splice(i,1); // Remove it from the array.
                break;
            }
        }
        this.length--; // Decrement cookie length

        // Actually delete the cookie
        document.cookie = key + "=; max-age=0";
    };

    // Remove all cookies
    this.clear = function() {
        var i = 0;
        for(; i < keys.length; i++) {
            document.cookie = keys[i] + "=; max-age=0";
        }

        // Reset our internal state
        cookies = {};
        keys = [];
        this.length = 0;
    };
};
var cache = (typeof window.localStorage !== 'undefined') ? window.localStorage : new CookieStorage();
window.cache = cache;
var Utils = function() {
    var logger = logManager.getLogger("utils");

    this.getProperty = function(obj, property) {
        return ((typeof obj[property]) === 'undefined') ? null : obj[property];
    };

    this.callFunctionIfExist = function() {
        var args = Array.prototype.slice.call(arguments), func;
        func = args.shift();
        if (typeof (func) === 'function') {
            try {
                func.apply(null, args);
                return true;
            }
            catch (e) {
                logger.error("Exception occured:\n" + e.stack);
                return undefined;
            }
        }
        else {
            logger.info("Not a function:" + func);
            return -1;
        }
    };

    this.s4 = function() {
        return Math.floor((1 + Math.random()) * 0x10000).toString(16).substring(1);
    };

    this.extend = function(target, object) {
        var prop;
        for (prop in object) {
            if (object.hasOwnProperty(prop)) {
                target[prop] = object[prop];
            }
        }
        return target;
    };

    this.compose = function(base, extendme) {
        var prop;
        for (prop in base) {
            if (typeof base[prop] === 'function' && !extendme[prop]) {
                extendme[prop] = base[prop].bind(base);
            }
        }
    };

    /**
     * Similar to jQuery.param
     */
    this.param = function(object) {
        var encodedString = '',
            prop;
        for (prop in object) {
            if (object.hasOwnProperty(prop)) {
                if (encodedString.length > 0) {
                    encodedString += '&';
                }
                encodedString += encodeURI(prop + '=' + object[prop]);
            }
        }
        return encodedString;
    };

    this.getTimestamp = function() {
        return new Date().getTime();
    };

    function getPropertyValueIfExistsInObject(object, key) {
        var objId, retVal;
        if (object) {
            for (objId in object) {
                if (object.hasOwnProperty(objId)) {
                    if (objId === key) {
                        retVal = object[objId];
                    }
                    else if (typeof object[objId] === "object") {
                        retVal = getPropertyValueIfExistsInObject(object[objId], key);
                    }
                    if (retVal) {
                        break;
                    }
                }
            }
            return retVal;
        }
    }

    this.getPropertyValueIfExistsInObject = getPropertyValueIfExistsInObject;

    this.Queue = function() {

        var items;

        this.enqueue = function(item) {
            if (typeof(items) === 'undefined') {
                items = [];
            }
            items.push(item);
        };

        this.dequeue = function() {
            return items.shift();
        };

        this.peek = function() {
            return items[0];
        };

        this.size = function() {
            return typeof(items)==='undefined' ? 0 : items.length;
        };
    };

    this.getQueue = function(){
        return new this.Queue();
    };

};
var utils = new Utils();

/**
 * Function.prototype.bind function not supported in phantom.js (used for unit test specs),
 * this fix, provides support for this function.
 *
 * TODO: This function should be checked in new release of phantom.js and
 * should be removed if not necessary anymore
 */
if (!Function.prototype.bind) {
  Function.prototype.bind = function(oThis) {
    if (typeof this !== 'function') {
      // closest thing possible to the ECMAScript 5
      // internal IsCallable function
      throw new TypeError('Function.prototype.bind - what is trying to be bound is not callable');
    }

    var aArgs   = Array.prototype.slice.call(arguments, 1),
        fToBind = this,
        FNOP    = function() {},
        FBound  = function() {
          return fToBind.apply(this instanceof FNOP && oThis
                 ? this
                 : oThis,
                 aArgs.concat(Array.prototype.slice.call(arguments)));
        };

    FNOP.prototype = this.prototype;
    FBound.prototype = new FNOP();

    return FBound;
  };
}

if (__testonly__) { __testonly__.UtilsQueue = utils.Queue;}

var SDPParser = function() {
    var logger = logManager.getLogger("sdpParser"),
            self, mediaDescriptions, sessionDescription,
            nl = "\n", lf = "\r";

    this.init = function(sdpData) {
        self = this;
        self.sessionDescription = {};
        self.mediaDescriptions = [];
        self.sdp = sdpData;
        self.parseSDP();
        self.setSessionDescriptionAttributes();
        self.setMediaDescriptionsAttributes();
    };


    this.parseSDP = function() {
        var descriptions = [], index = 1, mediaDescription;
        descriptions = self.sdp.split(/^(?=m=)/m);
        self.sessionDescription.data = descriptions[0];
        for (index; index < descriptions.length; index++) {
            mediaDescription = {};
            mediaDescription.data = descriptions[index];
            self.mediaDescriptions.push(mediaDescription);
        }
    };

    this.setSessionDescriptionAttributes = function() {
        var line = 0, sessionDescriptions = self.sessionDescription.data.split(/\r\n|\r|\n/), connectionData;

        for (line; line < sessionDescriptions.length; line++) {
            if ((sessionDescriptions[line].match("^e="))) {
                self.sessionDescription.email = sessionDescriptions[line].split('=')[1];
            }
            else if ((sessionDescriptions[line].match("^c="))) {
                connectionData = sessionDescriptions[line].split('=')[1];
                self.sessionDescription.connection = connectionData;
                self.sessionDescription.ip = connectionData.split(' ')[2];
            }
        }
    };

    this.setMediaDescriptionsAttributes = function() {
        var line = 0, mediaDescriptionIndex, mediaDescriptionAttributes, mediaData, connectionData;

        for (mediaDescriptionIndex in self.mediaDescriptions) {
            if (self.mediaDescriptions.hasOwnProperty(mediaDescriptionIndex)) {
                mediaDescriptionAttributes = self.mediaDescriptions[mediaDescriptionIndex].data.split(/\r\n|\r|\n/);
                this.mediaDescriptions[mediaDescriptionIndex].direction = "sendrecv";
                for (line in mediaDescriptionAttributes) {
                    if (mediaDescriptionAttributes.hasOwnProperty(line)) {
                        //direction default sendrcv setle
                        if ((mediaDescriptionAttributes[line].match("^m="))) {
                            mediaData = mediaDescriptionAttributes[line].split('=')[1];
                            self.mediaDescriptions[mediaDescriptionIndex].media = mediaData;
                            self.mediaDescriptions[mediaDescriptionIndex].port = mediaData.split(' ')[1];
                        }
                        else if ((mediaDescriptionAttributes[line].match("^a=sendrecv")) || (mediaDescriptionAttributes[line].match("^a=sendonly")) || (mediaDescriptionAttributes[line].match("^a=recvonly")) || (mediaDescriptionAttributes[line].match("^a=inactive"))) {
                            self.mediaDescriptions[mediaDescriptionIndex].direction = mediaDescriptionAttributes[line].split('=')[1];
                        }
                        else if ((mediaDescriptionAttributes[line].match("^c="))) {
                            connectionData = mediaDescriptionAttributes[line].split('=')[1];
                            self.mediaDescriptions[mediaDescriptionIndex].connection = connectionData;
                            self.mediaDescriptions[mediaDescriptionIndex].ip = connectionData.split(' ')[2];
                        }
                    }
                }
            }
        }

    };

    this.isHold = function(isRemote) {
        var isHold = false, ip, media_index = 0, mediaDesc, direction;
        for (media_index in self.mediaDescriptions) {
            if (self.mediaDescriptions.hasOwnProperty(media_index)) {
                mediaDesc = this.mediaDescriptions[media_index];
                if (mediaDesc.ip) {
                    ip = mediaDesc.ip;
                }
                else {
                    if (self.sessionDescription.ip) {
                        ip = self.sessionDescription.ip;
                    }
                }

                if (mediaDesc.port !== 0) {
                    if ((mediaDesc.direction === "inactive") ||
                        ( (mediaDesc.direction === "sendonly") && isRemote) ||
                        ( (mediaDesc.direction === "recvonly") && !isRemote) ||
                        (ip === "0.0.0.0") ) {
                        isHold = true;
                    }
                    else {
                        isHold = false;
                        break;
                    }
                }
            }
        }
        return isHold;
    };

    this.isRemoteHold = function() {
        return this.isHold(true);
    };

    this.isLocalHold = function() {
        return this.isHold(false);
    };

    this.getSessionDescription = function() {
        return self.sessionDescription;
    };

    this.getMediaDescriptions = function() {
        return self.mediaDescriptions;
    };

    this.isSdpHas = function(pSdp, type) {
        var result = false;

        if (pSdp.indexOf(CONSTANTS.SDP.M_LINE + type) !== -1) {
            result = true;
            return result;
        }

        return result;
    };

    this.isSdpHasAudio = function(pSdp) {
        return this.isSdpHas(pSdp, CONSTANTS.STRING.AUDIO);
    };

    this.isSdpHasVideo = function(pSdp) {
        return this.isSdpHas(pSdp, CONSTANTS.STRING.VIDEO);
    };

    this.isSdpHasMediaWithExpectedPort = function(pSdp, type, port) {
        return pSdp.indexOf(CONSTANTS.SDP.M_LINE + type + " " + port) !== -1;
    };

    this.isSdpHasAudioWithZeroPort = function(pSdp) {
        return this.isSdpHasMediaWithExpectedPort(pSdp, CONSTANTS.STRING.AUDIO, 0);
    };

    this.isSdpHasVideoWithZeroPort = function(pSdp) {
        return this.isSdpHasMediaWithExpectedPort(pSdp, CONSTANTS.STRING.VIDEO, 0);
    };

    this.isSdpHasAudioWithOnePort = function(pSdp) {
        return this.isSdpHasMediaWithExpectedPort(pSdp, CONSTANTS.STRING.AUDIO, 1);
    };

    this.isSdpHasVideoWithOnePort = function(pSdp) {
        return this.isSdpHasMediaWithExpectedPort(pSdp, CONSTANTS.STRING.VIDEO, 1);
    };

    this.isSdpHasAudioWithNinePort = function(pSdp) {
        return this.isSdpHasMediaWithExpectedPort(pSdp, CONSTANTS.STRING.AUDIO, 9);
    };

    this.isSdpHasVideoWithNinePort = function(pSdp) {
        return this.isSdpHasMediaWithExpectedPort(pSdp, CONSTANTS.STRING.VIDEO, 9);
    };

    this.replaceZeroVideoPortWithOne = function(pSdp) {
        if (this.isSdpHasVideoWithZeroPort(pSdp)) {
            pSdp = pSdp.replace(CONSTANTS.SDP.M_LINE + CONSTANTS.STRING.VIDEO + " 0 ", CONSTANTS.SDP.M_LINE + CONSTANTS.STRING.VIDEO + " 1 ");
        }
        return pSdp;
    };

    this.getSdpDirection = function(pSdp, type) {
        var substr = "", descriptions = [], index,
                direction = CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE, logmsg;

        logmsg = function(state) {
            logger.info("getSdpDirection: type= " + type + " state= " + state);
        };

        if (!this.isSdpHas(pSdp, type)) {
            logmsg(direction);
            return direction;
        }

        if (this.isSdpHasMediaWithExpectedPort(pSdp, type, 0)) {
            // return if media port is 0
            logmsg(direction);
            return direction;
        }

        descriptions = pSdp.split(/^(?=m=)/m);
        for (index = 0; index < descriptions.length; index++) {
            substr = descriptions[index];
            if (substr.indexOf(CONSTANTS.SDP.M_LINE + type) !== -1) {
                if (substr.indexOf(CONSTANTS.SDP.A_LINE + CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE) !== -1) {
                    direction = CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE;
                    logmsg(direction);
                    return direction;
                } else if (substr.indexOf(CONSTANTS.SDP.A_LINE + CONSTANTS.WEBRTC.MEDIA_STATE.SEND_ONLY) !== -1) {
                    direction = CONSTANTS.WEBRTC.MEDIA_STATE.SEND_ONLY;
                    logmsg(direction);
                    return direction;
                } else if (substr.indexOf(CONSTANTS.SDP.A_LINE + CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY) !== -1) {
                    direction = CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY;
                    logmsg(direction);
                    return direction;
                } else if (substr.indexOf(CONSTANTS.SDP.A_LINE + CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE) !== -1) {
                    logmsg(direction);
                    return direction;
                }
                direction = CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE;
                return direction;
            }
        }
        direction = CONSTANTS.WEBRTC.MEDIA_STATE.NOT_FOUND;
        logmsg(direction);
        return direction;
    };

    this.getAudioSdpDirection = function(pSdp) {
        return this.getSdpDirection(pSdp, CONSTANTS.STRING.AUDIO);
    };

    this.getVideoSdpDirection = function(pSdp) {
        return this.getSdpDirection(pSdp, CONSTANTS.STRING.VIDEO);
    };

    this.isAudioSdpDirectionInactive = function(pSdp) {
        return this.getAudioSdpDirection(pSdp) === CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE;
    };

    this.isAudioSdpDirectionSendrecv = function(pSdp) {
        return this.getAudioSdpDirection(pSdp) === CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE;
    };

    this.isAudioSdpDirectionSendonly = function(pSdp) {
        return this.getAudioSdpDirection(pSdp) === CONSTANTS.WEBRTC.MEDIA_STATE.SEND_ONLY;
    };

    this.isAudioSdpDirectionRecvonly = function(pSdp) {
        return this.getAudioSdpDirection(pSdp) === CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY;
    };

    this.isSdpContainsAudioDirection = function(pSdp) {
        return this.getAudioSdpDirection(pSdp) !== CONSTANTS.WEBRTC.MEDIA_STATE.NOT_FOUND;
    };

    this.isVideoSdpDirectionInactive = function(pSdp) {
        return this.getVideoSdpDirection(pSdp) === CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE;
    };

    this.isVideoSdpDirectionSendrecv = function(pSdp) {
        return this.getVideoSdpDirection(pSdp) === CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE;
    };

    this.isVideoSdpDirectionSendonly = function(pSdp) {
        return this.getVideoSdpDirection(pSdp) === CONSTANTS.WEBRTC.MEDIA_STATE.SEND_ONLY;
    };

    this.isVideoSdpDirectionRecvonly = function(pSdp) {
        return this.getVideoSdpDirection(pSdp) === CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY;
    };

    this.isSdpContainsVideoDirection = function(pSdp) {
        return this.getVideoSdpDirection(pSdp) !== CONSTANTS.WEBRTC.MEDIA_STATE.NOT_FOUND;
    };

    this.changeDirection = function(pSdp, directionBefore, directionAfter, type) {
        var sdp = "", substr, descriptions = [], index,
                msg = "changeDirection: before= " + directionBefore + " after= " + directionAfter;

        if (directionBefore === directionAfter) {
            //no need to change direction
            return pSdp;
        }

        if (type === undefined || type === null) {
            logger.info(msg + " for all media types");
        } else if (directionBefore !== this.getSdpDirection(pSdp, type)) {
            //Ignore changing the direction if the "directionBefore" and existing directions do not match
            return pSdp;
        } else {
            logger.info(msg + " type= " + type);
        }

        descriptions = pSdp.split(/^(?=m=)/m);
        for (index = 0; index < descriptions.length; index++) {
            substr = descriptions[index];
            if (type === undefined || type === null || substr.indexOf(CONSTANTS.SDP.M_LINE + type) !== -1) {
                substr = substr.replace(CONSTANTS.SDP.A_LINE + directionBefore, CONSTANTS.SDP.A_LINE + directionAfter);
            }
            sdp = sdp + substr;
        }

        return sdp;
    };

    this.updateSdpDirection = function(pSdp, type, direction) {
        logger.info("updateSdpDirection: type= " + type + " direction= " + direction);
        var beforeDirection = this.getSdpDirection(pSdp, type);
        return this.changeDirection(pSdp, beforeDirection, direction, type);
    };

    this.updateAudioSdpDirection = function(pSdp, direction) {
        logger.info("updateSdpDirection: type= " + CONSTANTS.STRING.AUDIO + " direction= " + direction);
        var beforeDirection = this.getSdpDirection(pSdp, CONSTANTS.STRING.AUDIO);
        return this.changeDirection(pSdp, beforeDirection, direction, CONSTANTS.STRING.AUDIO);
    };

    this.updateVideoSdpDirection = function(pSdp, direction) {
        logger.info("updateSdpDirection: type= " + CONSTANTS.STRING.VIDEO + " direction= " + direction);
        var beforeDirection = this.getSdpDirection(pSdp, CONSTANTS.STRING.VIDEO);
        return this.changeDirection(pSdp, beforeDirection, direction, CONSTANTS.STRING.VIDEO);
    };

    this.updateAudioSdpDirectionToInactive = function(pSdp) {
        return this.updateAudioSdpDirection(pSdp, CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE);
    };

    this.updateVideoSdpDirectionToInactive = function(pSdp) {
        return this.updateVideoSdpDirection(pSdp, CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE);
    };

    this.isSdpHasDirection = function(pSdp) {
        var sr_indx, so_indx, ro_indx, in_indx;
        sr_indx = pSdp.indexOf(CONSTANTS.SDP.A_LINE + CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE, 0);
        so_indx = pSdp.indexOf(CONSTANTS.SDP.A_LINE + CONSTANTS.WEBRTC.MEDIA_STATE.SEND_ONLY, 0);
        ro_indx = pSdp.indexOf(CONSTANTS.SDP.A_LINE + CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY, 0);
        in_indx = pSdp.indexOf(CONSTANTS.SDP.A_LINE + CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE, 0);
        return (sr_indx + 1) + (so_indx + 1) + (ro_indx + 1) + (in_indx + 1) === 0 ? false : true;
    };

    this.isSdpEnabled = function(pSdp, type) {
        var direction, msg = "isSdpEnabled for type " + type + ": ", result = false;

        if (this.isSdpHasMediaWithExpectedPort(pSdp, type, 0)) {
            // return if media port is 0
            logger.info(msg + result);
            return result;
        }
        if (type === CONSTANTS.STRING.VIDEO) {
            direction = this.getVideoSdpDirection(pSdp);
            if (direction === CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY || direction === CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE) {
                logger.info(msg + result);
                return result;
            }
        }
        if (this.isSdpHas(pSdp, type)) {
            result = true;
        }
        logger.info(msg + result);
        return result;
    };

    this.isAudioSdpEnabled = function(pSdp) {
        return this.isSdpEnabled(pSdp, CONSTANTS.STRING.AUDIO);
    };

    this.isVideoSdpEnabled = function(pSdp) {
        return this.isSdpEnabled(pSdp, CONSTANTS.STRING.VIDEO);
    };

    this.isSdpVideoReceiveEnabled = function(pSdp) {
        var direction, msg = "isSdpVideoReceiveEnabled: ", result = false;

        if (pSdp.indexOf(CONSTANTS.SDP.M_LINE + CONSTANTS.STRING.VIDEO + " 0") !== -1) {
            logger.info(msg + result);
            return result;
        }

        direction = this.getVideoSdpDirection(pSdp);
        if (direction === CONSTANTS.WEBRTC.MEDIA_STATE.SEND_ONLY || direction === CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE) {
            logger.info(msg + result);
            return result;
        }

        if (pSdp.indexOf(CONSTANTS.SDP.M_LINE + CONSTANTS.STRING.VIDEO) !== -1) {
            result = true;
            logger.info(msg + result);
            return result;
        }

        logger.info(msg + result);
        return result;
    };

    this.updateH264Level = function(pSdp) {
        var sdp = "", substr = "", descriptions = [], index, reg = /\r\n|\r|\n/m, video_arr, i, new_substr = "", elm, elm_array;

        descriptions = pSdp.split(/^(?=m=)/m);
        for (index = 0; index < descriptions.length; index++) {
            substr = descriptions[index];
            if (substr.indexOf(CONSTANTS.SDP.M_LINE + CONSTANTS.STRING.VIDEO) !== -1) {
                video_arr = substr.split(reg);
                for (i = 0; i < video_arr.length; i++) {
                    elm = video_arr[i];
                    if (elm && elm.indexOf("a=rtpmap:") !== -1 && elm.indexOf("H264") !== -1) {
                        elm_array = elm.split(/\:| /m);
                        elm = elm + CONSTANTS.STRING.CARRIAGE_RETURN + CONSTANTS.STRING.NEW_LINE;
                        elm = elm + "a=fmtp:" + elm_array[1] + " profile-level-id=428014;";
                        elm = elm + CONSTANTS.STRING.CARRIAGE_RETURN + CONSTANTS.STRING.NEW_LINE;
                        // Workaround for issue 1603.
                    } else if (elm && elm !== "") {
                        elm = elm + CONSTANTS.STRING.CARRIAGE_RETURN + CONSTANTS.STRING.NEW_LINE;
                    }
                    new_substr = new_substr + elm;
                }
                substr = new_substr;
            }
            sdp = sdp + substr;
        }
        return sdp;
    };

    this.isSdpVideoCandidateEnabled = function(pSdp) {
        var msg = "isSdpVideoCandidateEnabled: ", result = false;

        if (this.isSdpHasVideoWithZeroPort(pSdp)) {
            logger.info(msg + result);
            return result;
        } else if (this.isVideoSdpDirectionInactive(pSdp)) {
            logger.info(msg + result);
            return result;
        } else if (!this.isSdpHasVideo(pSdp)) {
            result = true;
            logger.info(msg + result);
            return true;
        }

        logger.info(msg + result);
        return result;
    };

    this.deleteFingerprintFromSdp = function(sdp, isDtlsEnabled) {
        if (isDtlsEnabled) {
            return sdp;
        }
        while (sdp.indexOf("a=fingerprint:") !== -1) {
            sdp = sdp.replace(/(a=fingerprint:[\w\W]*?(:\r|\n))/, "");
        }
        return sdp;
    };

    this.deleteCryptoFromSdp = function(sdp, isDtlsEnabled) {
        if (!isDtlsEnabled) {
            return sdp;
        }
        while (sdp.indexOf("a=crypto:") !== -1) {
            sdp = sdp.replace(/(a=crypto:[\w\W]*?(:\r|\n))/, "");
        }
        return sdp;
    };

    this.deleteCryptoZeroFromSdp = function(sdp) {
        while (sdp.indexOf("a=crypto:0") !== -1) {
            sdp = sdp.replace(/(a=crypto:0[\w\W]*?(:\r|\n))/, "");
        }
        return sdp;
    };

    /*
     * performVP8RTCPParameterWorkaround: this function will handle missing VP8 RTCP params mostly observed in plugin configuration
     * It will do nothing and work correctly, when plugin webrtc base is upgraded to Chrome 37
     * check for "ccm fir".   If not exists, add "a=rtcp-fb:* ccm fir",
     * check for "nack pli".  If not exists, add "a=rtcp-fb:* nack pli",
     * check for "nack".      If not exists, add "a=rtcp-fb:* nack",
     * check for "goog-remb". If not exists, add "a=rtcp-fb:* goog-remb",
     * @param {type} pSdp
     */
    this.performVP8RTCPParameterWorkaround = function(pSdp) {
        var splitArray, newSdp, tempSdp, vp8PayloadType;

        if(pSdp.indexOf("VP8/90000") === -1) { //TODO
            return pSdp;
        }

        vp8PayloadType = this.getVP8PayloadType(pSdp); //TODO

        tempSdp = pSdp.replace("a=rtcp-fb:" + vp8PayloadType + " nack pli",
                               "a=rtcp-fb:" + vp8PayloadType + " no_ack_pli");  //It will use to identify nack pli

        tempSdp = tempSdp.replace("a=rtcp-fb:" + vp8PayloadType + " nack",
                                  "a=rtcp-fb:" + vp8PayloadType + " none_ack");  //It will use to identify nack

        splitArray = pSdp.split("VP8/90000");

        if(splitArray.length <= 1){
            return pSdp;
        }

        newSdp = splitArray[0] + "VP8/90000";
        if(pSdp.indexOf("a=rtcp-fb:" + vp8PayloadType + " ccm fir") === -1) {
            logger.debug("performVP8RTCPParameterWorkaround : Adding a=rtcp-fb:" + vp8PayloadType + " ccm fir");
            newSdp = newSdp + "\r\na=rtcp-fb:" + vp8PayloadType + " ccm fir";
        }
        if(tempSdp.indexOf("a=rtcp-fb:" + vp8PayloadType + " no_ack_pli") === -1) {
            logger.debug("performVP8RTCPParameterWorkaround : Adding a=rtcp-fb:" + vp8PayloadType + " nack pli");
            newSdp = newSdp + "\r\na=rtcp-fb:" + vp8PayloadType + " nack pli";
        }
        if(tempSdp.indexOf("a=rtcp-fb:" + vp8PayloadType + " none_ack") === -1) {
            logger.debug("performVP8RTCPParameterWorkaround : Adding a=rtcp-fb:" + vp8PayloadType + " nack");
            newSdp = newSdp + "\r\na=rtcp-fb:" + vp8PayloadType + " nack";
        }
        if(pSdp.indexOf("a=rtcp-fb:" + vp8PayloadType + " goog-remb") === -1) {
            logger.debug("performVP8RTCPParameterWorkaround : Adding a=rtcp-fb:" + vp8PayloadType + " goog-remb");
            newSdp = newSdp + "\r\na=rtcp-fb:" + vp8PayloadType + " goog-remb";
        }

        pSdp = newSdp + splitArray[1];
        return pSdp;
    };

    /*
     * updateAudioCodec: removes codecs listed in config file from codec list. Required for DTMF until the bug is fixed.
     * @param {type} pSdp
     */
    this.updateAudioCodec = function(pSdp) {
        var sdp = "", substr = "", descriptions = [], index, reg = /\r\n|\r|\n/m, audio_arr, i, new_substr = "", elm,
                remcodec, regExpCodec, codecsToRemove = [], j, remrtpmap;

        remrtpmap = "";
        descriptions = pSdp.split(/^(?=m=)/m);
        for (index = 0; index < descriptions.length; index++) {
            substr = descriptions[index];
            if (this.isSdpHasAudio(substr)) {
                audio_arr = substr.split(reg);
                for (i = 0; i < audio_arr.length; i++) {
                    elm = audio_arr[i];
                    if (elm && this.isSdpHasAudio(elm)) {
                        // remove audio codecs given in config file from m=audio line
                        codecsToRemove = fcsConfig.codecsToRemove;
                        if (codecsToRemove !== undefined) {
                            for (j = 0; j < codecsToRemove.length; j++) {
                                remcodec = codecsToRemove[j];
                                regExpCodec = new RegExp(" " + remcodec, "g");
                                elm = elm.replace(regExpCodec, "");

                                if (j !== 0) {
                                    remrtpmap = remrtpmap + "|";
                                }
                                remrtpmap = remrtpmap + remcodec;
                            }
                        }
                        elm = elm + lf + nl;
                        // Workaround for issue 1603.
                    } else if (elm && elm.indexOf("a=fmtp") !== -1) {
                        elm = elm.replace(/a=fmtp[\w\W]*/, "");
                    } else if (elm && elm !== "") {
                        elm = elm + lf + nl;
                    }
                    new_substr = new_substr + elm;
                }
                substr = new_substr;
            }
            sdp = sdp + substr;
        }
        // remove rtpmap of removed codecs
        if (remrtpmap !== "") {
            regExpCodec = new RegExp("a=rtpmap:(?:" + remrtpmap + ").*\r\n", "g");
            sdp = sdp.replace(regExpCodec, "");
        }
        return sdp;
    };

    /*
     * removeAudioCodec: removes given codec type from sdp.
     * @param {type} pSdp
     * @param {type} codecToRemove
     */
    this.removeAudioCodec = function(pSdp, codecToRemove) {
        var sdp = "", substr = "", descriptions = [], index, reg = /\r\n|\r|\n/m, audio_arr, i,
            new_substr = "", elm, elm2, regExpCodec;

        descriptions = pSdp.split(/^(?=m=)/m);
        for (index = 0; index < descriptions.length; index++) {
            substr = descriptions[index];
            if (this.isSdpHasAudio(substr)) {
                audio_arr = substr.split(reg);
                for (i = 0; i < audio_arr.length; i++) {
                    elm = audio_arr[i];
                    if (elm && this.isSdpHasAudio(elm)) {
                        // remove given audio codec from m=audio line
                        regExpCodec = new RegExp(" " + codecToRemove + "($| )", "m");
                        elm2 = audio_arr[i].split(/RTP[\w\W]*/);
                        elm = elm.replace(/(\m=audio+)\s(\w+)/, "");
                        elm = elm.trim();
                        elm = elm.replace(regExpCodec, " ");
                        elm = elm2[0] +elm + lf + nl;
                        // Workaround for issue 1603.
                    } else if (elm && elm.indexOf("a=fmtp:" + codecToRemove) !== -1) {
                        elm = elm.replace(/a=fmtp[\w\W]*/, "");
                    } else if (elm && elm.indexOf("a=rtpmap:" + codecToRemove) !== -1) {
                        elm = elm.replace(/a=rtpmap[\w\W]*/, "");
                    } else if (elm && elm.indexOf("a=rtcp-fb:" + codecToRemove) !== -1) {
                        elm = elm.replace(/a=rtcp-fb[\w\W]*/, "");
                    } else if (elm && elm !== "") {
                        elm = elm + lf + nl;
                    }
                    new_substr = new_substr + elm;
                }
                substr = new_substr;
            }
            sdp = sdp + substr;
        }
        return sdp;
    };

    /*
     * removeRTXCodec: this function will remove rtx video codec
     */
    this.removeRTXCodec = function(pSdp) {
        var rtxPayloadType,vp8SSRC, rtxSSRC;

        vp8SSRC = this.getVp8Ssrc(pSdp);
        logger.debug("vp8SSRC = " + vp8SSRC);

        rtxSSRC = this.getRtxSsrc(pSdp);
        logger.debug("rtxSSRC = " + rtxSSRC);

        pSdp = this.removeSsrcId(pSdp,rtxSSRC);

        pSdp = pSdp.replace(/(a=ssrc-group:FID[\w\W]*?(:\r|\n))/g, "");

        if(pSdp.indexOf("rtx/90000") === -1) {
            return pSdp;
        }

        rtxPayloadType = this.getRTXPayloadType(pSdp);

        logger.debug("removeRTXCodec : Removing rtx video codec " + rtxPayloadType);
        pSdp = this.removeVideoCodec(pSdp, rtxPayloadType);

        return pSdp;
    };

    this.getVp8Ssrc = function(pSdp) {
        var splitArray, ssrcGroupArray, ssrcArray, i, reg = /\r\n|\r|\n/m;

        if (pSdp.indexOf("a=ssrc-group:FID ") === -1) {
            return -1;
        }

        splitArray = pSdp.split("a=ssrc-group:FID ");
        ssrcGroupArray = splitArray[1].split(reg);
        ssrcArray = ssrcGroupArray[0].split(" ");

        for (i = 0; i < ssrcArray.length; i++) {
            logger.debug("ssrcArray[" + i + "] : " + ssrcArray[i]);
        }

        return ssrcArray[0];
    };

    this.getRtxSsrc = function(pSdp) {
        var splitArray, ssrcGroupArray, ssrcArray, i, reg = /\r\n|\r|\n/m;

        if (pSdp.indexOf("a=ssrc-group:FID ") === -1) {
            return -1;
        }

        splitArray = pSdp.split("a=ssrc-group:FID ");
        ssrcGroupArray = splitArray[1].split(reg);
        ssrcArray = ssrcGroupArray[0].split(" ");

        for (i = 0; i < ssrcArray.length; i++) {
            logger.debug("ssrcArray[" + i + "] : " + ssrcArray[i]);
        }

        return ssrcArray[1];
    };

    /*
     * removeSsrcId: removes given SSRC ID from sdp.
     */
    this.removeSsrcId = function(pSdp, ssrcId) {
        var sdp = "", reg = /\r\n|\r|\n/m, ssrc_arr, i, new_substr = "", elm;

        ssrc_arr = pSdp.split(reg);
        for (i = 0; i < ssrc_arr.length; i++) {
            elm = ssrc_arr[i];
            if (elm && elm.indexOf("a=ssrc:" + ssrcId) !== -1) {
                elm = elm.replace(/a=ssrc:[\w\W]*/, "");
            } else if (elm && elm !== "") {
                elm = elm + lf + nl;
            }
            new_substr = new_substr + elm;
        }
        sdp = new_substr;

        return sdp;
    };

    /*
     * removeG722Codec: this function will remove G722 audio codec
     * @param {type} pSdp
     */
    this.removeG722Codec = function(pSdp) {
        /*
        *   this function is added because of chrome-v39 bug.
        *   need to be checked with chrome-v40.
        *   should be deleted if not needed.
        */
       /* var g722PayloadType;

        if ((pSdp.indexOf("G722/8000") === -1) && (pSdp.indexOf("G722/16000") === -1)) {
            return pSdp;
        }

        g722PayloadType = this.getG7228000PayloadType(pSdp);

        if (g722PayloadType !== -1) {
            logger.debug("removeG722Codec : Removing G722/8000 video codec " + g722PayloadType);
            pSdp = this.removeAudioCodec(pSdp, g722PayloadType);
        }
        g722PayloadType = this.getG72216000PayloadType(pSdp);
        if (g722PayloadType !== -1) {
            logger.debug("removeG722Codec : Removing G722/16000 video codec " + g722PayloadType);
            pSdp = this.removeAudioCodec(pSdp, g722PayloadType);
        }
        */
        return pSdp;
    };

    /*
     * setMediaActPass - use it to adjust offer sdp
     * @param {type} sdp
     */
    this.setMediaActPass = function(sdp, isDtlsEnabled) {
        if (!isDtlsEnabled) {
            return sdp;
        }
        logger.debug("setMediaActPass: ");
        while (sdp.indexOf("a=setup:active") !== -1) {
            logger.debug("a=setup:active to a=setup:actpass");
            sdp = sdp.replace("a=setup:active", "a=setup:actpass");
        }
        while (sdp.indexOf("a=setup:passive") !== -1) {
            logger.debug("a=setup:passive to a=setup:actpass");
            sdp = sdp.replace("a=setup:passive", "a=setup:actpass");
        }
        return sdp;
    };

    this.fixLocalTelephoneEventPayloadType = function(call, pSdp) {
        var newSdp;

        call.localTelephoneEvent8000PayloadType = this.getTelephoneEventCode(pSdp, "8000", call.localTelephoneEvent8000PayloadType);
        call.localTelephoneEvent16000PayloadType = this.getTelephoneEventCode(pSdp, "16000", call.localTelephoneEvent16000PayloadType);

        newSdp = this.fixTelephoneEventPayloadType(pSdp, "8000", call.localTelephoneEvent8000PayloadType);
        newSdp = this.fixTelephoneEventPayloadType(newSdp, "16000", call.localTelephoneEvent16000PayloadType);

        return newSdp;
    };

    this.fixRemoteTelephoneEventPayloadType = function(call, pSdp) {
        var newSdp;

        call.remoteTelephoneEvent8000PayloadType = this.getTelephoneEventCode(pSdp, "8000", call.remoteTelephoneEvent8000PayloadType);
        call.remoteTelephoneEvent16000PayloadType = this.getTelephoneEventCode(pSdp, "16000", call.remoteTelephoneEvent16000PayloadType);

        newSdp = this.fixTelephoneEventPayloadType(pSdp, "8000", call.remoteTelephoneEvent8000PayloadType);
        newSdp = this.fixTelephoneEventPayloadType(newSdp, "16000", call.remoteTelephoneEvent16000PayloadType);

        return newSdp;
    };

    this.getTelephoneEventCode = function(pSdp, rate, oldCode) {
        var telephoneEventPayloadType;

        if(this.isSdpHasTelephoneEvent(pSdp, rate)) {
            telephoneEventPayloadType = this.getTelephoneEventPayloadType(pSdp,rate);
            if (!oldCode) {
                return telephoneEventPayloadType;
            } else {
                return oldCode;
            }
        }

        return null;
    };

    /*
     * Replaces telephone event code in pSdp with the oldCode
     * This is needed for WebRTC engine compatibility
     * Ex: Negotitation is firstly done with 126, but then the call server sends an offer with 96
     * @param {type} pSdp
     * @param {type} rate
     * @param {type} oldCode
     */
    this.fixTelephoneEventPayloadType = function(pSdp, rate, oldCode) {
        var telephoneEventPayloadType, newSdp;

        if(this.isSdpHasTelephoneEvent(pSdp, rate)) {
            telephoneEventPayloadType = this.getTelephoneEventPayloadType(pSdp,rate);
            if (!oldCode) {
                oldCode = telephoneEventPayloadType;
            } else if (oldCode !== telephoneEventPayloadType) {
                newSdp = this.replaceTelephoneEventPayloadType(pSdp, oldCode, telephoneEventPayloadType);
                return newSdp;
            }
        }

        return pSdp;
    };

    this.getTelephoneEventPayloadType = function(pSdp,rate) {
        return this.getPayloadTypeOf("telephone-event/" + rate,pSdp);
    };

    this.getPayloadTypeOf = function(codecString,pSdp) {
        var splitArray, rtpmapArray, payloadTypeArray;

        if(pSdp.indexOf(codecString) === -1) {
            return -1;
        }

        splitArray = pSdp.split(codecString);
        rtpmapArray = splitArray[0].split("a=rtpmap:");
        payloadTypeArray = rtpmapArray[rtpmapArray.length-1].split(" ");

        logger.debug("getPayloadTypeOf(" + codecString + ") = " + payloadTypeArray[0]);

        return payloadTypeArray[0];
    };

    /*
     * Replaces new telephone event code in pSdp with the oldCode
     * This is needed for WebRTC engine compatibility
     * If an offer has a different telephone event code than what is already negotiated in that session, webrtc engine gives error
     * Ex: Negotitation is firstly done with 126, but then the call server sends an offer with 96
     * @param {type} pSdp
     * @param {type} oldCode
     * @param {type} newCode
     */
    this.replaceTelephoneEventPayloadType = function(pSdp, oldCode, newCode) {
        var finalsdp, regex, matches, tempAudioLine, descriptions, index, substr, partialsdp = "", number = "";

        if (!pSdp || (pSdp.indexOf("telephone-event") === -1)) {
            return pSdp;
        }

        regex = /^\.*(a=rtpmap:)(\d*)( telephone-event[ \w+ ]*[ \/+ ]*[ \w+ ]*)\r\n?/m;

        /* example: matches= ["a=rtpmap:96 telephone-event/8000\r\n", "a=rtpmap:", "96", " telephone-event/8000"] */

        if (oldCode === newCode) { // telephone event has not changed
            // nothing has changed, return without any changes
            return pSdp;
        }

        // telephone event has changed
        finalsdp = pSdp;

        // replace rtpmap
        regex = new RegExp("^\\.*a=rtpmap:" + newCode + " telephone-event[ \\/+ ]*([ \\w+ ]*)\\r\n", "m");
        matches = finalsdp.match(regex);
        if (matches !== null && matches.length >= 2 && matches[1] !== "") {
            number = matches[1];
        } else {
            number = 8000;
        }
        finalsdp = finalsdp.replace(regex,'a=rtpmap:' + oldCode + ' telephone-event/' + number + '\r\n');

        // replace audio line
        regex = new RegExp("^\\.*(m=audio )[ \\w+ ]*[ \\/+ ]*[ \\w+ ]*( " + newCode + ")", "mg");
        matches = finalsdp.match(regex);

        if (matches !== null && matches.length >= 1 && matches[0] !== "") {
            tempAudioLine = matches[0];
            tempAudioLine = tempAudioLine.replace(newCode, oldCode);
            finalsdp = finalsdp.replace(regex, tempAudioLine);
        }

        // replace fmtp
        // only audio section needs to be considered, do not change video section
        descriptions = finalsdp.split(/^(?=m=)/m);
        for (index = 0; index < descriptions.length; index++) {
            substr = descriptions[index];
            if (this.isSdpHasAudio(substr)) {
                regex = new RegExp("^\\.*a=fmtp:" + newCode, "mg");
                substr = substr.replace(regex, 'a=fmtp:' + oldCode);
            }
            partialsdp = partialsdp + substr;
        }
        if (partialsdp !== "") {
            finalsdp = partialsdp;
        }
        logger.debug("replaceTelephoneEventPayloadType: newcode " + newCode + " is replaced with oldcode " + oldCode);
        return finalsdp;
    };

    /*
     * Replaces opus codec in pSdp with the default codec number 109
     * (TODO: get the codec from config.json)
     * This is needed for trancoder enabled peer-to-peer scenarios
     * transcoder only accepts opus codec that it offers
     * @param {type} pSdp
     */
    this.replaceOpusCodec = function (pSdp) {
        var regex, matches, tempAudioLine, oldCodecNumber = "",
            defaultCodecNumber = 109, descriptions, index, substr, partialsdp = "";

        if (!pSdp || (pSdp.indexOf("opus") === -1)) {
            return pSdp;
        }

        regex = /^\.*(a=rtpmap:)(\d*)( opus)/m;
        /* example: matches= ["a=rtpmap:109 opus/48000/2\r\n", "a=rtpmap:", "111", " opus/48000/2"] */

        matches = pSdp.match(regex);
        if (matches !== null && matches.length >= 3 && matches[2] !== "") {
            oldCodecNumber = matches[2];
        }
        else {
            logger.warn("sdp has opus without codec number");
        }
        // replace rtpmap
        pSdp = pSdp.replace(regex, 'a=rtpmap:' + defaultCodecNumber + ' opus');

        // replace audio line
        regex = new RegExp("^\\.*(m=audio )[ \\w+ ]*[ \\/+ ]*[ \\w+ ]*( " + oldCodecNumber + ")", "mg");
        matches = pSdp.match(regex);

        if (matches !== null && matches.length >= 1 && matches[0] !== "") {
            tempAudioLine = matches[0];
            tempAudioLine = tempAudioLine.replace(oldCodecNumber, defaultCodecNumber);
            pSdp = pSdp.replace(regex, tempAudioLine);
        }

        // replace fmtp
        // only audio section needs to be considered, do not change video section
        descriptions = pSdp.split(/^(?=m=)/m);
        for (index = 0; index < descriptions.length; index++) {
            substr = descriptions[index];
            if (this.isSdpHasAudio(substr)) {
                regex = new RegExp("^\\.*a=fmtp:" + oldCodecNumber, "mg");
                substr = substr.replace(regex, 'a=fmtp:' + defaultCodecNumber);
            }
            partialsdp = partialsdp + substr;
        }
        if (partialsdp !== "") {
            pSdp = partialsdp;
        }
        logger.debug("replaceOpusCodec: new codec= " + defaultCodecNumber);
        return pSdp;
    };

    this.getG7228000PayloadType = function(pSdp) {
        return this.getPayloadTypeOf("G722/8000",pSdp);
    };

    this.getVP8PayloadType = function(pSdp) {
        return this.getPayloadTypeOf("VP8/90000",pSdp);
    };

    this.getG72216000PayloadType = function(pSdp) {
        return this.getPayloadTypeOf("G722/16000",pSdp);
    };

    this.getRTXPayloadType = function(pSdp) {
        return this.getPayloadTypeOf("rtx/90000", pSdp);
    };

    this.isSdpHasTelephoneEvent = function(pSdp, rate){
        return pSdp.indexOf("telephone-event/" + rate) !== -1;
    };

    this.isSdpHasVP8Codec = function(pSdp){
        return pSdp.indexOf("VP8/90000") !== -1;
    };

    this.performG722ParameterWorkaround = function(pSdp) {
       /* var g722PayloadType;

        if(pSdp.indexOf("G722/8000") === -1) {
            return pSdp;
        }

        g722PayloadType = this.getG7228000PayloadType(pSdp);

        pSdp = pSdp.replace("a=rtpmap:" + g722PayloadType + " G722/8000",
                            "a=rtpmap:" + g722PayloadType + " G722/16000");
        */
        return pSdp;
    };

    /*
     * checkSupportedVideoCodecs
     *
     * checks video codec support status and remove video m-line if no supported video codec is available
     * @param {type} pSdp
     * @param {type} localOfferSdp
     */
    this.checkSupportedVideoCodecs = function(pSdp, localOfferSdp) {
        var newSdp;
        if (this.isVideoCodecsSupported(pSdp)) {
            return pSdp;
        } else {
            if (localOfferSdp) {
                newSdp = this.removeAllVideoCodecs(pSdp);
                newSdp = this.addVP8Codec(newSdp, localOfferSdp);
                newSdp = this.updateSdpVideoPort(newSdp, false);
                newSdp = this.performVideoPortZeroWorkaround(newSdp);
            } else {
                //******************************************************
                //Changing video port to 0 when there is no supported
                //video codecs is not working in webrtc library
                //******************************************************
                if (!this.isSdpHasVP8Codec(pSdp)) {
                    if (pSdp.indexOf(CONSTANTS.SDP.M_LINE + CONSTANTS.STRING.VIDEO + " 0 ", 0) !== -1) {
                        newSdp = this.addVP8Codec(pSdp, newSdp);
                    } else {
                        //this is required for PCC and meetme with video
                        newSdp = this.updateSdpVideoPort(pSdp, false);
                        newSdp = this.addVP8Codec(newSdp, newSdp);
                    }
                } else {
                    newSdp = this.removeVideoDescription(pSdp);      //this is required for PCC and meetme with video
                }
            }

            return newSdp;
        }
    };

    /*
     * isVideoCodecsSupported: this function checks supported video codecs are listed in m=video line
     * Supported video codecs are :
     *      VP8     default supported codec
     *      H264    if plugin_mode is webrtch264 or legacyh264
     *      @param {type} pSdp
     */
    this.isVideoCodecsSupported = function(pSdp) {

        if(this.isSdpHasVP8Codec(pSdp)) {
            return true;
        }

        return false;
    };

    this.removeAllVideoCodecs = function(pSdp) {
        var regex, matches, codecs, newSdp, index;

        regex = new RegExp("^\\.*(m=video )(\\d*)( RTP/SAVPF )([ \\w+ ]*[ \\/+ ]*[ \\w+ ])\\r\n", "m");

        newSdp = pSdp;
        matches = newSdp.match(regex);

        if (matches !== null && matches.length >= 5 && matches[0] !== "") {
            codecs = matches[4].split(" ");
            for (index = 0; index < codecs.length; index++) {
                logger.debug("codec[" + index + "] : " + codecs[index]);
                newSdp = this.removeVideoCodec(newSdp, codecs[index]);
            }
        }

        return newSdp;
    };

    /*
     * removeVideoCodec: removes given codec type from sdp.
     * @param {type} pSdp
     * @param {type} codecToRemove
     */
    this.removeVideoCodec = function(pSdp, codecToRemove) {
        var sdp = "", substr = "", descriptions = [], index, reg = /\r\n|\r|\n/m, video_arr, i,
            new_substr = "", elm, regExpCodec;

        descriptions = pSdp.split(/^(?=m=)/m);
        for (index = 0; index < descriptions.length; index++) {
            substr = descriptions[index];
            if (this.isSdpHasVideo(substr)) {
                video_arr = substr.split(reg);
                for (i = 0; i < video_arr.length; i++) {
                    elm = video_arr[i];
                    if (elm && this.isSdpHasVideo(elm)) {
                        // remove given video codec from m=video line
                        regExpCodec = new RegExp(" " + codecToRemove, "g");
                        elm = elm.replace(regExpCodec, "");
                        elm = elm + lf + nl;
                        // Workaround for issue 1603.
                    } else if (elm && elm.indexOf("a=fmtp:" + codecToRemove) !== -1) {
                        elm = elm.replace(/a=fmtp[\w\W]*/, "");
                    } else if (elm && elm.indexOf("a=rtpmap:" + codecToRemove) !== -1) {
                        elm = elm.replace(/a=rtpmap[\w\W]*/, "");
                    } else if (elm && elm.indexOf("a=rtcp-fb:" + codecToRemove) !== -1) {
                        elm = elm.replace(/a=rtcp-fb[\w\W]*/, "");
                    } else if (elm && elm !== "") {
                        elm = elm + lf + nl;
                    }
                    new_substr = new_substr + elm;
                }
                substr = new_substr;
            }
            sdp = sdp + substr;
        }
        return sdp;
    };

    /*
     * addVP8Codec: adds missing VP8 Codec
     * @param {type} pSdp
     * @param {type} offerSdp
     */
    this.addVP8Codec = function(pSdp, offerSdp) {
        var sdp = "", substr="",descriptions=[],index,
            reg = /\r\n|\r|\n/m, video_arr, i, new_substr = "",
            vp8PayloadType, codecType, elm,
            videoUFRAGParam, videoPWDParam, ice_ufrag, ice_pwd;

        if(this.isSdpHasVP8Codec(pSdp)) {
            return pSdp;
        }

        descriptions= pSdp.split(/^(?=m=)/m);
        for(index=0;index<descriptions.length;index++){
            substr = descriptions[index];
            if(this.isSdpHasVideo(substr)){
                if (offerSdp &&
                    this.isSdpHasVideo(offerSdp) &&
                    this.isSdpHasVP8Codec(offerSdp)) {
                        vp8PayloadType = this.getVP8PayloadType(offerSdp);
                        if (substr.indexOf("a=rtpmap:" + vp8PayloadType) !== -1) {
                            this.removeSdpLineContainingText(substr,"a=rtpmap:" + vp8PayloadType);
                        }
                } else {
                    codecType = 100;
                    while (substr.indexOf("a=rtpmap:" + codecType) !== -1) {
                        codecType = codecType + 1;
                    }
                    vp8PayloadType = codecType;
                }
                video_arr = substr.split(reg);
                for(i=0;i<video_arr.length;i++){
                    elm = video_arr[i];
                    if (elm && this.isSdpHasVideo(elm)) {
                        if (elm.indexOf(vp8PayloadType) === -1) {
                            elm = elm + " " + vp8PayloadType;
                        }
                        elm = elm  + lf + nl + "a=rtpmap:" + vp8PayloadType + " VP8/90000" + lf + nl;
                    } else if (elm && elm !== "") {
                        elm = elm + lf + nl;
                    }
                    new_substr = new_substr + elm;
                }
                substr = new_substr;
            }
            sdp = sdp + substr;
        }

        videoUFRAGParam = this.checkICEParams(sdp, "video", CONSTANTS.SDP.ICE_UFRAG);
	if(videoUFRAGParam < 2){
            ice_ufrag = this.getICEParams(sdp, CONSTANTS.SDP.ICE_UFRAG, false);
            if (ice_ufrag) {
                sdp = this.restoreICEParams(sdp, "video", CONSTANTS.SDP.ICE_UFRAG, ice_ufrag);
            }
	}
	videoPWDParam = this.checkICEParams(sdp, "video", CONSTANTS.SDP.ICE_PWD);
	if(videoPWDParam < 2){
            ice_pwd = this.getICEParams(sdp, CONSTANTS.SDP.ICE_PWD, false);
            if (ice_pwd) {
                sdp = this.restoreICEParams(sdp, "video", CONSTANTS.SDP.ICE_PWD, ice_pwd);
            }
	}

        return this.performVP8RTCPParameterWorkaround(sdp);
    };

    this.removeSdpLineContainingText = function(pSdp, containing_text) {
        var i,
            splitArray = pSdp.split(nl);

        pSdp = splitArray[0] + nl;
        for (i = 1; i < splitArray.length - 1; i++) {
            if (splitArray[i].indexOf(containing_text) !== -1) {
                logger.debug("removed line which contains " + containing_text);
            }
            else {
                pSdp += splitArray[i] + nl;
            }
        }
        return pSdp;
    };

    this.removeVideoDescription = function(pSdp) {
        var sdp = "", substr="", descriptions=[], index;

        descriptions= pSdp.split(/^(?=m=)/m);
        for(index=0;index<descriptions.length;index++){
            substr = descriptions[index];
            if(!this.isSdpHasVideo(substr)){
                sdp = sdp + substr;
            } else {
                logger.debug("removeVideoDescription : m=video description removed");
            }
        }
        return sdp;
    };

    /*
     * updateSdpVideoPort
     * @param {type} pSdp
     * @param {type} status
     */
    this.updateSdpVideoPort = function(pSdp, status) {
        var r_sdp, port_text;

        logger.debug("updateSdpVideoPort: status= " + status);

        r_sdp = pSdp;

        if (status) {
            port_text = CONSTANTS.SDP.M_LINE + CONSTANTS.STRING.VIDEO + " 1";
        }
        else {
            port_text = CONSTANTS.SDP.M_LINE + CONSTANTS.STRING.VIDEO + " 0";
            r_sdp = this.updateSdpDirection(r_sdp, CONSTANTS.STRING.VIDEO, CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE);
        }

        if (this.isSdpHasVideo(r_sdp)) {
            r_sdp = r_sdp.replace(/m=video [0-9]+/, port_text);
        }

        return r_sdp;
    };

    /*
     * performVideoPortZeroWorkaround - apply this when term side sends an answer with video port 0
     * @param {type} pSdp
     */
    this.performVideoPortZeroWorkaround = function(pSdp) {

        if (!this.isSdpHasVideoWithZeroPort(pSdp)) {
            return pSdp;
        }
        pSdp = this.addSdpMissingCryptoLine (pSdp);
        pSdp = this.replaceZeroVideoPortWithOne(pSdp);

        //chrome38 fix
        pSdp = this.updateVideoSdpDirectionToInactive(pSdp);

        return pSdp;
    };

    // Issue      : Meetme conference failed due to a webrtc bug
    //              When video is sent in SDP with 0 without a=crypto line(SDES) in SDP,
    //              hold scenario for meetme failed.
    // Workaround : Add dummy a=crypto or a=fingerprint line to solve the issue with a workaround
    // Note       : fingerprint(DTLS enabled) may still fails on meetme. This is known issue as below:
    //              https://code.google.com/p/webrtc/issues/detail?id=2316
    //              Check with Chrome 37
    this.addSdpMissingCryptoLine = function(sdp) {
        var mediaSplit, audioLines, cryptLine = null, reg = /\r\n|\r|\n/m, i;

        // If there is no "m=video 0" line, sdp should not be modified
        if (sdp.indexOf(CONSTANTS.SDP.M_LINE + CONSTANTS.STRING.VIDEO + " 0 ", 0) === -1) {
            return sdp;
        }

        mediaSplit = sdp.split(CONSTANTS.SDP.M_LINE + CONSTANTS.STRING.VIDEO);

        audioLines = mediaSplit[0].split(reg);
        for (i = 0; i < audioLines.length; i++) {
            if ((audioLines[i].indexOf(CONSTANTS.SDP.A_LINE + CONSTANTS.SDP.CRYPTO) !== -1) || (audioLines[i].indexOf(CONSTANTS.SDP.A_LINE + CONSTANTS.SDP.FINGERPRINT) !== -1)) {
                cryptLine = audioLines[i];
                break;
            }
        }

        if (cryptLine === null) {
            return sdp;
        }

        if (mediaSplit[0].indexOf(CONSTANTS.SDP.A_LINE + CONSTANTS.SDP.CRYPTO) !== -1) {
            if (mediaSplit[1].indexOf(CONSTANTS.SDP.A_LINE + CONSTANTS.SDP.CRYPTO, 0) === -1) {
                mediaSplit[1] += cryptLine + "\n";
                logger.debug("addSdpMissingCryptoLine : crypto line is added : " + cryptLine);
            }
        } else if (mediaSplit[0].indexOf(CONSTANTS.SDP.A_LINE + CONSTANTS.SDP.FINGERPRINT, 0) !== -1) {
            if (mediaSplit[1].indexOf(CONSTANTS.SDP.A_LINE + CONSTANTS.SDP.FINGERPRINT, 0) === -1) {
                //DTLS is enabled, even adding fingerprint line in SDP,
                //meetme scenario fails. This is known issue and followed
                //by webrtc for DTLS enabled scenarios :
                //https://code.google.com/p/webrtc/issues/detail?id=2316
                mediaSplit[1] += cryptLine + "\na=setup:passive\n";
                logger.debug("addSdpMissingCryptoLine : dtls lines are added : " + cryptLine + "and a=setup:passive");
                logger.debug("dtls enabled: known issue by webrtc may be fixed! Check it");
            }
        }
        sdp = mediaSplit.join(CONSTANTS.SDP.M_LINE + CONSTANTS.STRING.VIDEO);
        return sdp;
    };

    this.checkICEParams = function(pSdp, mediaType, type) {
	var parse1, parse2;

	parse1 = pSdp.split('m=video');
	if(parse1.length < 2){
		return 0;
	}

        switch (type) {
            case CONSTANTS.SDP.ICE_UFRAG:
                if(mediaType === "audio"){
			parse2 = parse1[0].split('a=ice-ufrag:');
		}else{
			parse2 = parse1[1].split('a=ice-ufrag:');
		}
                break;
            case CONSTANTS.SDP.ICE_PWD:
		if(mediaType === "audio"){
			parse2 = parse1[0].split('a=ice-pwd:');
		}else{
			parse2 = parse1[1].split('a=ice-pwd:');
		}
                break;
            default:
                return 0;
	}

        return parse2.length;
    };

    this.getICEParams = function(pSdp, type, isVideo) {
        var parse1, parse2, parse3, param;

        switch (type) {
            case CONSTANTS.SDP.ICE_UFRAG:
                parse1 = pSdp.split('a=ice-ufrag:');
                break;
            case CONSTANTS.SDP.ICE_PWD:
                parse1 = pSdp.split('a=ice-pwd:');
                break;
            default:
                return undefined;
        }

        if(isVideo){
            if(parse1[2] !== undefined) { /*"....a=ice-....a=ice-...."*/
                parse2 = parse1[2];
                parse3 = parse2.split('a=');
                param = parse3[0];
                return param; /*return video ice params*/
            } else {
                return undefined;
            }
        } else {
            if(parse1[1] !== undefined) { /*"....a=ice-....a=ice-...."*/
                parse2 = parse1[1];
                parse3 = parse2.split('a=');
                param = parse3[0];
                return param;
            } else {
                return undefined;
            }
        }
    };

    this.restoreICEParams = function(pSdp, mediaType, type, new_value) {
        var sdp = "", substr, index, parse1;

        parse1 = pSdp.split('m=video');
	if(parse1.length < 2){
            return pSdp;
	}

        for (index = 0; index < parse1.length; index++)
        {
            substr = parse1[index];
            if(index === 0)
            {
                if(mediaType === "audio"){
			substr = substr + 'a=' + type + new_value;
		}
		sdp = sdp + substr;
            }
            if(index === 1)
            {
                if(mediaType === "video"){
			substr = substr + 'a=' + type + new_value;
		}
		sdp = sdp + 'm=video' + substr;
            }
        }
        return sdp;
    };

    this.updateICEParams = function (pSdp, type, new_value) {
        var sdp = "", subsdp = "", substr, index, num,
                parse1, parse2, parse3, param=null;

        switch(type)
        {
            case CONSTANTS.SDP.ICE_UFRAG:
                parse1 = pSdp.split('a=ice-ufrag:');
                break;
            case CONSTANTS.SDP.ICE_PWD:
                parse1 = pSdp.split('a=ice-pwd:');
                break;
            default:
                return pSdp;
        }

        for (index = 0; index < parse1.length; index++)
        {
            substr = parse1[index];
            if (index === 2)
            {
                parse2 = substr.split('a=');

                for (num = 0; num < parse2.length; num++)
                {
                    parse3 = parse2[num];
                    if(num===0)
                    {
                        parse2[num]= new_value;
                        subsdp = subsdp + parse2[num];
                    }else
                    {
                        subsdp = subsdp + 'a=' + parse2[num];
                    }
                }
                substr = subsdp;
                sdp = sdp + substr;
            }else
            {
                sdp = sdp + substr + 'a=' + type;
            }
        }
        return sdp;
    };

    this.checkIceParamsLengths = function(newSdp, oldSdp) {
        var ice_ufrag, ice_pwd;
        ice_ufrag = this.getICEParams(newSdp, CONSTANTS.SDP.ICE_UFRAG, true);
        ice_pwd = this.getICEParams(newSdp, CONSTANTS.SDP.ICE_PWD, true);

        if (ice_ufrag && ice_ufrag.length < 4) { /*RFC 5245 the ice-ufrag attribute can be 4 to 256 bytes long*/
            ice_ufrag = this.getICEParams(oldSdp, CONSTANTS.SDP.ICE_UFRAG, true);
            if (ice_ufrag) {
                newSdp = this.updateICEParams(newSdp, CONSTANTS.SDP.ICE_UFRAG, ice_ufrag);
            }
        }

        if (ice_pwd && ice_pwd.length < 22) { /*RFC 5245 the ice-pwd attribute can be 22 to 256 bytes long*/
            ice_pwd = this.getICEParams(oldSdp, CONSTANTS.SDP.ICE_PWD, true);
            if (ice_pwd < 22) {
                newSdp = this.updateICEParams(newSdp, CONSTANTS.SDP.ICE_PWD, ice_pwd);
            }
        }
        return newSdp;
    };

    /*
     * isSdpVideoSendEnabled
     * @param {type} pSdp
     */
    this.isSdpVideoSendEnabled = function(pSdp) {
        var direction,
            msg = "isSdpVideoSendEnabled: ",
            result = false;

        if (!this.isSdpEnabled(pSdp, CONSTANTS.STRING.VIDEO)) {
            logger.debug(msg + result);
            return result;
        }

        direction = this.getSdpDirectionLogging(pSdp, CONSTANTS.STRING.VIDEO, false);
        if (direction === CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE ||
            direction === CONSTANTS.WEBRTC.MEDIA_STATE.SEND_ONLY) {
            result = true;
            logger.debug(msg + result);
            return result;
        }

        logger.debug(msg + result);
        return result;
    };

    this.getSdpDirectionLogging = function(pSdp, type, logging) {
        var substr = "", descriptions = [], index,
            direction = CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE, logmsg;

        logmsg = function(state) {
            if (logging) {
                logger.debug("getSdpDirection: type= " + type + " state= " + state);
            }
        };

        if (pSdp.indexOf(CONSTANTS.SDP.M_LINE + type) === -1) {
            logmsg(direction);
            return direction;
        }

        if (pSdp.indexOf(CONSTANTS.SDP.M_LINE + type + " 0") !== -1) {
            logmsg(direction);
            return direction;
        }

        descriptions = pSdp.split(/^(?=m=)/m);
        for (index = 0; index < descriptions.length; index++) {
            substr = descriptions[index];
            if (substr.indexOf(CONSTANTS.SDP.M_LINE + type) !== -1) {
                if (substr.indexOf(CONSTANTS.SDP.A_LINE + CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE) !== -1) {
                    direction = CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE;
                    logmsg(direction);
                    return direction;
                } else if (substr.indexOf(CONSTANTS.SDP.A_LINE + CONSTANTS.WEBRTC.MEDIA_STATE.SEND_ONLY) !== -1) {
                    direction = CONSTANTS.WEBRTC.MEDIA_STATE.SEND_ONLY;
                    logmsg(direction);
                    return direction;
                } else if (substr.indexOf(CONSTANTS.SDP.A_LINE + CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY) !== -1) {
                    direction = CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY;
                    logmsg(direction);
                    return direction;
                } else if (substr.indexOf(CONSTANTS.SDP.A_LINE + CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE) !== -1) {
                    logmsg(direction);
                    return direction;
                }
                direction = CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE;
                return direction;
            }
        }
        direction = CONSTANTS.WEBRTC.MEDIA_STATE.NOT_FOUND;
        logmsg(direction);
        return direction;
    };

    /*
     * remove only video ssrc from the sdp
     * this is a workaround to hear audio in a peer-to-peer call
     * @param {type} pSdp
     */
    this.deleteInactiveVideoSsrc = function(pSdp) {
        var videoSdp = [];

        if (this.isSdpHas(pSdp, CONSTANTS.STRING.VIDEO)) {
            videoSdp = pSdp.split(CONSTANTS.SDP.M_LINE + CONSTANTS.STRING.VIDEO);
            if (videoSdp[1] !== null) {
                videoSdp[1] = this.deleteSsrcFromSdp(videoSdp[1]);
            }
        } else {
            return pSdp;
        }
        return videoSdp[0] + CONSTANTS.SDP.M_LINE + CONSTANTS.STRING.VIDEO + videoSdp[1];
    };

    /*
     * deleteSsrcFromSdp - delete ssrc from the sdp, use it when there is video continuity issue
     * @param {type} sdp
     */
    this.deleteSsrcFromSdp = function(sdp) {
        while (sdp.indexOf("a=ssrc") !== -1) {
            sdp = sdp.replace(/(a=ssrc[\w\W]*?(:\r|\n))/, "");
        }
        return sdp;
    };

    /*
     * setMediaPassive - use it to adjust answer sdp
     * @param {type} sdp
     */
    this.setMediaPassive = function(sdp, isDtlsEnabled) {
        if (!isDtlsEnabled) {
            return sdp;
        }
        logger.debug("setMediaPassive: ");
        while (sdp.indexOf("a=setup:actpass") !== -1) {
            logger.debug("a=setup:actpass to a=setup:passive");
            sdp = sdp.replace("a=setup:actpass", "a=setup:passive");
        }
        return sdp;
    };

    /*
     * This is a transcoder bug that only happens on native webrtc.
     * We can remove it once it's fixed.
     * This function will remove one of the lines if there are two
     * concecutive same lines that contains "nack pli"
     * TODO tolga remove once this issue is fixed
     */
    this.removeSdpPli = function(pSdp) {
        var i, splitArray = pSdp.split(nl);

        pSdp = splitArray[0] + nl;
        for (i = 1; i < splitArray.length - 1; i++) {
            if (splitArray[i - 1] === splitArray[i] && splitArray[i].indexOf(CONSTANTS.SDP.NACKPLI) !== -1) {
                logger.debug("removed extra nack pli line");
            }
            else {
                pSdp += splitArray[i] + nl;
            }
        }
        return pSdp;
    };

    /*
     * performVP8BandwidthWorkaround: this function will remove following lines which causes
     * webrtc failed to process error on Chrome Beta with PCC call. will be soon observed on Chrome stable.
     * check for "b=AS:0".        If exists, remove,
     */
    this.performVP8BandwidthWorkaround = function(pSdp) {
        if (!this.isSdpHasVP8Codec(pSdp)) {
            return pSdp;
        }

        if (pSdp.indexOf("b=AS:0") !== -1) {
            logger.debug("performVP8BandwidthWorkaround : Removing b=AS:0");
            pSdp = this.removeSdpLineContainingText(pSdp, "b=AS:0");
        }

        return pSdp;
    };

    /*
     *
     * @param {type} pSdp
     * @param {type} oSdp
     * @returns pSdp
     */
    this.checkAndRestoreICEParams = function(pSdp, oSdp) {
        var audioUFRAGParam, audioPWDParam, videoUFRAGParam, videoPWDParam, ice_ufrag, ice_pwd;

        audioUFRAGParam = this.checkICEParams(pSdp, CONSTANTS.STRING.AUDIO, CONSTANTS.SDP.ICE_UFRAG);
        if (audioUFRAGParam < 2) {
            ice_ufrag = this.getICEParams(oSdp, CONSTANTS.SDP.ICE_UFRAG, false);
            if (ice_ufrag) {
                pSdp = this.restoreICEParams(pSdp, CONSTANTS.STRING.AUDIO, CONSTANTS.SDP.ICE_UFRAG, ice_ufrag);
            }
        }
        audioPWDParam = this.checkICEParams(pSdp, CONSTANTS.STRING.AUDIO, CONSTANTS.SDP.ICE_PWD);
        if (audioPWDParam < 2) {
            ice_pwd = this.getICEParams(oSdp, CONSTANTS.SDP.ICE_PWD, false);
            if (ice_pwd) {
                pSdp = this.restoreICEParams(pSdp, CONSTANTS.STRING.AUDIO, CONSTANTS.SDP.ICE_PWD, ice_pwd);
            }
        }
        videoUFRAGParam = this.checkICEParams(pSdp, CONSTANTS.STRING.VIDEO, CONSTANTS.SDP.ICE_UFRAG);
        if (videoUFRAGParam < 2) {
            ice_ufrag = this.getICEParams(oSdp, CONSTANTS.SDP.ICE_UFRAG, false);
            if (ice_ufrag) {
                pSdp = this.restoreICEParams(pSdp, CONSTANTS.STRING.VIDEO, CONSTANTS.SDP.ICE_UFRAG, ice_ufrag);
            }
        }
        videoPWDParam = this.checkICEParams(pSdp, CONSTANTS.STRING.VIDEO, CONSTANTS.SDP.ICE_PWD);
        if (videoPWDParam < 2) {
            ice_pwd = this.getICEParams(oSdp, CONSTANTS.SDP.ICE_PWD, false);
            if (ice_pwd) {
                pSdp = this.restoreICEParams(pSdp, CONSTANTS.STRING.VIDEO, CONSTANTS.SDP.ICE_PWD, ice_pwd);
            }
        }
        return pSdp;
    };

    this.incrementVersion = function(psdp) {
        var oline=[], newoline ="", index, version, regExpCodec, arr=[];
        logger.debug(" incrementVersion");

        // o=- 937770930552268055 2 IN IP4 127.0.0.1
        oline = psdp.match('o=(?:.+?[\\s.,;]+){2}([^\\s.,;]+)'); // get the 3rd

        version = oline[1];
        version = +version; // convert to int
        version = version + 1;

        arr = oline[0].split(" ");
        arr[arr.length - 1] = version; // set new version to last element
        for (index = 0; index < arr.length; index++) {
            if (index !== 0) {
                newoline = newoline + " ";
            }
            newoline = newoline + arr[index];
        }

        regExpCodec = new RegExp(oline[0], "g");
        psdp = psdp.replace(regExpCodec, newoline);

        return psdp;
    };

    /*
     * escalateSdpDirection for type:audio or video
     * @param {type} pSdp
     * @param {type} type
     */
    this.escalateSdpDirection = function(pSdp, type) {
        var direction = this.getSdpDirectionLogging(pSdp, type, false);
        logger.debug("escalateSdpDirection: type= " + type + " direction= " + direction);
        if (direction === CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY) {
            return this.changeDirection(pSdp, direction, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE, type);
        } else if (direction === CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE) {
            return this.changeDirection(pSdp, direction, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_ONLY, type);
        }
        return pSdp;
    };

    /*
     * deescalateSdpDirection for type:audio or video
     * @param {type} pSdp
     * @param {type} type
     */
    this.deescalateSdpDirection = function(pSdp, type) {
        var direction = this.getSdpDirectionLogging(pSdp, type, false);
        logger.debug("deescalateSdpDirection: type= " + type + " direction= " + direction);
        if (direction === CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE) {
            return this.changeDirection(pSdp, direction, CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY, type);
        } else if (direction === CONSTANTS.WEBRTC.MEDIA_STATE.SEND_ONLY) {
            return this.changeDirection(pSdp, direction, CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE, type);
        }
        return pSdp;
    };

    this.isIceLite = function(pSdp) {
        if (pSdp && pSdp.indexOf("a=ice-lite") !== -1) {
            return true;
        }
        return false;
    };

    /*
     * Updates the version in tosdp with the one retrieved from fromsdp with incrementing
     *
     */
    this.updateVersion = function(fromsdp, tosdp) {
        var fromOline = [], toOline = [], newoline = "", index, version, regExpCodec, arr = [];

        logger.debug(" updateVersion called...");

        // o=- 937770930552268055 2 IN IP4 127.0.0.1
        fromOline = fromsdp.match('o=(?:.+?[\\s.,;]+){2}([^\\s.,;]+)'); // get the 3rd
        toOline = tosdp.match('o=(?:.+?[\\s.,;]+){2}([^\\s.,;]+)'); // get the 3rd

        if (fromOline) {
            version = fromOline[1];
        } else {
            logger.warn("updateVersion called with wrong fromSdp!!");
            return tosdp;
        }

        version = +version; // convert to int
        version = version + 1;

        logger.debug(" updateVersion fromVersion incremented: " + version);

        arr = toOline[0].split(" ");
        arr[arr.length - 1] = version; // set new version to last element
        for (index = 0; index < arr.length; index++) {
            if (index !== 0) {
                newoline = newoline + " ";
            }
            newoline = newoline + arr[index];
        }

        regExpCodec = new RegExp(toOline[0], "g");
        tosdp = tosdp.replace(regExpCodec, newoline);

        return tosdp;
    };

    // TODO: Method below assumes to receive only one video m-line, need to correct this logic.
    this.copyCandidatesToTheNewLocalSdp = function(oldSdp, newSdp) {
        var oldSplitSdp = [], newSplitSdp = [], oldVideoSdp, newVideoSdp,
                oldAudioSdp, newAudioSdp;

        oldSplitSdp = oldSdp.split(CONSTANTS.SDP.M_LINE + CONSTANTS.STRING.VIDEO);
        newSplitSdp = newSdp.split(CONSTANTS.SDP.M_LINE + CONSTANTS.STRING.VIDEO);

        oldAudioSdp = oldSplitSdp[0];
        oldVideoSdp = oldSplitSdp[1] !== undefined ? CONSTANTS.SDP.M_LINE + CONSTANTS.STRING.VIDEO + oldSplitSdp[1] : undefined;
        newAudioSdp = newSplitSdp[0];
        newVideoSdp = newSplitSdp[1] !== undefined ? CONSTANTS.SDP.M_LINE + CONSTANTS.STRING.VIDEO + newSplitSdp[1] : undefined;

        newAudioSdp = this.copyCandidates(oldAudioSdp, newAudioSdp);

        if (oldVideoSdp !== undefined && newVideoSdp !== undefined) {
            newVideoSdp = this.copyCandidates(oldVideoSdp, newVideoSdp);
        }

        if (newVideoSdp !== undefined) {
            return newAudioSdp + newVideoSdp;
        }
        else {
            return newAudioSdp;
        }
    };

    this.copyCandidates = function(oldSdp, newSdp) {
        var mediaLines, reg = /\r\n|\r|\n/m, i, port;

        mediaLines = oldSdp.split(reg);

        for (i = 0; i < mediaLines.length; i++) {
            if (mediaLines[i].indexOf("a=candidate") !== -1 && newSdp.indexOf(("a=candidate") === -1)) {
                newSdp += mediaLines[i] + "\r\n";
            } else if (mediaLines[i].indexOf("c=IN") !== -1 && newSdp.indexOf(("c=IN IP4 0.0.0.0") !== -1)) {
                newSdp = newSdp.replace(/(c=[\w\W]*?(:\r|\n))/, mediaLines[i] + "\r\n");
            } else if ((mediaLines[i].indexOf("m=audio") !== -1) &&
                       (newSdp.indexOf(CONSTANTS.SDP.M_LINE + CONSTANTS.STRING.AUDIO + " 1 ") !== -1 ||
                        newSdp.indexOf(CONSTANTS.SDP.M_LINE + CONSTANTS.STRING.AUDIO + " 9 ") !== -1)) {
                port = mediaLines[i].split(" ")[1];

                newSdp = newSdp.replace(/m=audio \d/, CONSTANTS.SDP.M_LINE + CONSTANTS.STRING.AUDIO + " " + port);
            } else if ((mediaLines[i].indexOf("m=video") !== -1) &&
                       (newSdp.indexOf(CONSTANTS.SDP.M_LINE + CONSTANTS.STRING.VIDEO + " 1 ") !== -1 ||
                        newSdp.indexOf(CONSTANTS.SDP.M_LINE + CONSTANTS.STRING.VIDEO + " 9 ") !== -1)) {
                port = mediaLines[i].split(" ")[1];

                newSdp = newSdp.replace(/m=video \d/, CONSTANTS.SDP.M_LINE + CONSTANTS.STRING.VIDEO + " " + port);
            }
        }
        return newSdp;
    };

    /*
     * getSdpFromObject
     * There is a webrtc bug in Plugin.
     * sendrecv direction changed to recvonly for offer type sdps
     * This function is the workaround solution to get the correct sdp from the object
     * until webrtc bug in plugin is fixed.
     */
    this.getSdpFromObject = function(oSdp) {
        var sdp;
        sdp = oSdp.sdp;

        sdp = this.updateAudioSdpDirection(sdp, oSdp.audioDirection);
        sdp = this.updateVideoSdpDirection(sdp, oSdp.videoDirection);

        return sdp;
    };

    /*
     * deleteGoogleIceFromSdp - delete google-ice option from the sdp
     */
    this.deleteGoogleIceFromSdp = function(sdp) {
        sdp = sdp.replace(/(a=ice-options:google-ice[\w\W]*?(:\r|\n))/g, "");
        return sdp;
    };

    this.respondToRemoteSdpDirections = function(localSdp, remoteSdp) {
        localSdp = this.respondToRemoteMediaSdpDirection(localSdp, remoteSdp, CONSTANTS.STRING.AUDIO);
        localSdp = this.respondToRemoteMediaSdpDirection(localSdp, remoteSdp, CONSTANTS.STRING.VIDEO);

        return localSdp;
    };

    this.respondToRemoteMediaSdpDirection = function(localSdp, remoteSdp, type) {
        var remoteDirection;

        if (this.isSdpHas(remoteSdp, type)) {
            remoteDirection = this.getSdpDirection(remoteSdp, type);

            if (remoteDirection === CONSTANTS.WEBRTC.MEDIA_STATE.SEND_ONLY) {
                logger.debug(type + " sendonly -> recvonly");
                localSdp = this.updateSdpDirection(localSdp, type, CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY);
            }
            else if (remoteDirection === CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY) {
                logger.debug(type + " recvonly -> sendonly");
                localSdp = this.updateSdpDirection(localSdp, type, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_ONLY);
            }
            else if (remoteDirection === CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE) {
                logger.debug(type + " sendrecv -> sendrecv");
                localSdp = this.updateSdpDirection(localSdp, type, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE);
            }
            else if (remoteDirection === CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE) {
                logger.debug(type + " inactive -> inactive");
                localSdp = this.updateSdpDirection(localSdp, type, CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE);
            }
        }
        return localSdp;
    };

    this.isMediaPortReady = function(pSdp) {
        if (!this.isSdpHasAudioWithOnePort(pSdp) &&
            !this.isSdpHasAudioWithNinePort(pSdp)) {
            if (this.isSdpHasVideo(pSdp)) {
                if (!this.isSdpHasVideoWithOnePort(pSdp) &&
                    !this.isSdpHasVideoWithNinePort(pSdp)) {
                    return true;
                }
            }
            else {
                return true;
            }
        }
        return false;
    };

    // spidr sends both fingerprint and crypto at incoming call to the term side
    // delete the unnecessary one before setting remote description
    this.deleteFingerprintOrCrypto = function(sdp, isDtlsEnabled) {
        if (!sdp) {
            return sdp;
        }
        if (sdp.indexOf("a=crypto:") === -1 || sdp.indexOf("a=fingerprint:") === -1) {
            return sdp;
        }
        sdp = this.deleteCryptoFromSdp(sdp, isDtlsEnabled);
        sdp = this.deleteFingerprintFromSdp(sdp, isDtlsEnabled);

        return sdp;
    };
};

var sdpParser = new SDPParser();

if (__testonly__) { __testonly__.SDPParser = SDPParser; }
var ConnectivityService = function() {

    var CONNECTION_URL = "/rest/version/latest/isAlive";

    this.checkConnectivity = function(onSuccess, onFailure) {
        server.sendGetRequest({
                    url: getUrl() + CONNECTION_URL + "?" + utils.getTimestamp()
                }, onSuccess,
                onFailure);
    };

};
var connectivityService = new ConnectivityService();

var ConnectivityManager = function() {
    var logger = logManager.getLogger("connectivityManager"),
            PRIORITY = 1,
            DEFAULT_INTERVAL_VALUE = 10000,
            isConnected = true, connectivityTimer,
            connectivityHandler = null;

    function stopCheckConnectivityTimer() {
        logger.info("check connectivity timer is stopped.");
        clearInterval(connectivityTimer);
    }

    function onCheckConnectivitySuccess() {
        if (!isConnected) {
            isConnected = true;
            setConnected(isConnected);
            logger.trace("Connectivity re-established...");
            globalBroadcaster.publish(CONSTANTS.EVENT.CONNECTION_REESTABLISHED);
        }
    }

    function onCheckConnectivityFailure() {
        if (isConnected) {
            isConnected = false;
            setConnected(isConnected);
            logger.trace("Connectivity is lost...");
            globalBroadcaster.publish(CONSTANTS.EVENT.CONNECTION_LOST);
        }
    }

    function checkConnectivity() {
        try {
            connectivityHandler();
        }
        catch (e) {
            logger.trace("Exception occured while executing connecitivy handler: ", e);
        }
        connectivityService.checkConnectivity(onCheckConnectivitySuccess, onCheckConnectivityFailure);
    }


    function initConnectivityCheck(message) {
        var intervalValue = DEFAULT_INTERVAL_VALUE,
                handler = message.connectivity ? message.connectivity.handler : null,
                interval = message.connectivity ? message.connectivity.interval : null;
        if (handler && typeof handler === 'function') {
            connectivityHandler = handler;
        }

        if (interval) {
            intervalValue = interval;
        }

        stopCheckConnectivityTimer();
        connectivityTimer = setInterval(checkConnectivity, intervalValue);
    }

    globalBroadcaster.subscribe(CONSTANTS.EVENT.DEVICE_SUBSCRIPTION_STARTED, initConnectivityCheck, PRIORITY);
    globalBroadcaster.subscribe(CONSTANTS.EVENT.DEVICE_SUBSCRIPTION_ENDED, stopCheckConnectivityTimer, PRIORITY);
    globalBroadcaster.subscribe(CONSTANTS.EVENT.XHR_REQUEST_NOT_INITIALIZED, onCheckConnectivityFailure, PRIORITY);

};
var connectivityManager = new ConnectivityManager();

var WebRtcAdaptorModel = function() {
    var self = this, dtlsEnabled = false, iceServerUrl = "",
            containers = {video: "",
                localVideo: "",
                remoteVideo: "",
                defaultVideo: ""},
            mediaConstraints = {
                audio: false,
                video: false
            },
            mediaSources = {
                video: {
                    available: false,
                    width: "320",
                    height: "240"
                },
                audio: {
                    available: false
                }
            },
            initialized = false,
            rtcLibrary = {},
            language,
            localStream,
            logLevel = 4,
            peerCount = 0,
            pluginEnabled = false,
            h264Enabled = false;

    self.getH264Enabled = function (){
        return h264Enabled;
    };

    self.setH264Enabled = function (enabled){
        h264Enabled = enabled;
    };

    self.getIceServerUrl = function() {
        return iceServerUrl;
    };

    self.setIceServerUrl = function(url) {
        iceServerUrl = url;
    };

    self.isDtlsEnabled = function() {
        return dtlsEnabled;
    };

    self.setDtlsEnabled = function(enabled) {
        dtlsEnabled = enabled;
    };

    self.getVideoContainer = function() {
        return containers.video;
    };

    self.setVideoContainer = function(container) {
        containers.video = container;
    };

    self.getLocalVideoContainer = function() {
        return containers.localVideo;
    };

    self.setLocalVideoContainer = function(container) {
        containers.localVideo = container;
    };

    self.getRemoteVideoContainer = function() {
        return containers.remoteVideo;
    };

    self.setRemoteVideoContainer = function(container) {
        containers.remoteVideo = container;
    };

    self.getDefaultVideoContainer = function() {
        return containers.defaultVideo;
    };

    self.setDefaultVideoContainer = function(container) {
        containers.defaultVideo = container;
    };

    self.isInitialized = function() {
        return initialized;
    };

    self.setInitialized = function(value) {
        initialized = value === true ? true : false;
    };

    self.getRtcLibrary = function() {
        return rtcLibrary;
    };

    self.setRtcLibrary = function(library) {
        rtcLibrary = library;
    };

    self.getLocalStream = function() {
        return localStream;
    };

    self.setLocalStream = function(stream) {
        localStream = stream;
    };

    self.getLogLevel = function() {
        return logLevel;
    };

    self.setLogLevel = function(level) {
        logLevel = level;
    };

    self.getLanguage = function() {
        return language;
    };

    self.setLanguage = function(lang) {
        language = lang;
    };

    self.getMediaAudio = function() {
        return mediaConstraints.audio;
    };

    self.setMediaAudio = function(_audio) {
        mediaConstraints.audio = _audio;
    };

    self.getMediaVideo = function() {
        return mediaConstraints.video;
    };

    self.setMediaVideo = function(_video) {
        mediaConstraints.video = _video;
    };

    self.getVideoWidth = function() {
        return mediaSources.video.width;
    };

    self.setVideoWidth = function(_videoWidth) {
        mediaSources.video.width = _videoWidth;
    };

    self.getVideoHeight = function() {
        return mediaSources.video.height;
    };

    self.setVideoHeight = function(_videoHeight) {
        mediaSources.video.height = _videoHeight;
    };

    self.getVideoSourceAvailable = function() {
        return mediaSources.video.available;
    };

    self.setVideoSourceAvailable = function(_videoSourceAvailable) {
        mediaSources.video.available = _videoSourceAvailable;
    };

    self.getAudioSourceAvailable = function() {
        return mediaSources.audio.available;
    };

    self.setAudioSourceAvailable = function(_audioSourceAvailable) {
        mediaSources.audio.available = _audioSourceAvailable;
    };

    self.getPeerCount = function() {
        return peerCount;
    };

    self.setPeerCount = function(_peerCount) {
        peerCount = _peerCount;
    };

    self.isPluginEnabled = function() {
        return pluginEnabled;
    };

    self.setPluginEnabled = function(_isPluginEnabled) {
        pluginEnabled = _isPluginEnabled;
    };
};
if (__testonly__) { __testonly__.WebRtcAdaptorModel = WebRtcAdaptorModel; }
var WebRtcChromeAdaptorModel = function() {
    var self = this;
};
WebRtcChromeAdaptorModel.prototype = new WebRtcAdaptorModel();
if (__testonly__) { __testonly__.WebRtcChromeAdaptorModel = WebRtcChromeAdaptorModel; }
var WebRtcFirefoxAdaptorModel = function() {
    var self = this;
};
WebRtcFirefoxAdaptorModel.prototype = new WebRtcAdaptorModel();
if (__testonly__) { __testonly__.WebRtcFirefoxAdaptorModel = WebRtcFirefoxAdaptorModel; }
var WebRtcPluginAdaptorModel = function() {
    var self = this,
        //this variable will be always set by a plugin adaptor.
        pluginVersion={
            major:               0,
            minor:               0,

            min_revision:        0,
            min_build:           0,

            current_revision:    0,
            current_build:       0
        };

    self.getPluginVersion = function() {
        return pluginVersion;
    };

    self.setPluginVersion = function(version) {
        pluginVersion = version;
    };
};
WebRtcPluginAdaptorModel.prototype = new WebRtcAdaptorModel();
if (__testonly__) { __testonly__.WebRtcPluginAdaptorModel = WebRtcPluginAdaptorModel; }
var webRtcLibraryDecoratorImpl = function(target, _super) {
    var libraryObjWrapper = {};

    libraryObjWrapper.getUserMedia = target.getUserMedia;
    libraryObjWrapper.showSettingsWindow = target.showSettingsWindow;
    libraryObjWrapper.getURLFromStream = target.getURLFromStream;
    libraryObjWrapper.createRTCSessionDescription = function(type, sdp) {
        return target.createSessionDescription(type, sdp);
    };

    libraryObjWrapper.createRTCIceCandidate = function(candidate, type, number) {
        return target.createIceCandidate(candidate, type, number);
    };

    libraryObjWrapper.createRTCPeerConnection = function(stunturn, constraints) {
        return target.createPeerConnection(stunturn, constraints);
    };

    libraryObjWrapper.setLang = function(lang) {
        target.language = lang || "en";
    };

    libraryObjWrapper.checkMediaSourceAvailability = function(callback) {
        utils.callFunctionIfExist(callback, {videoSourceAvailable: (target.getVideoDeviceNames().length > 0) ? true : false,
            audioSourceAvailable: (target.getAudioOutDeviceNames().length > 0) ? true : false});
    };

    libraryObjWrapper.get_audioInDeviceCount = function() {
        return target.getAudioInDeviceNames().length;
    };

    libraryObjWrapper.get_audioOutDeviceCount = function() {
        return target.getAudioOutDeviceNames().length;
    };

    libraryObjWrapper.get_videoDeviceCount = function() {
        return target.getVideoDeviceNames().length;
    };

    libraryObjWrapper.set_logSeverityLevel = function(level) {
        target.logSeverityLevel = level;
        return true;
    };

    libraryObjWrapper.get_logSeverityLevel = function() {
        return target.logSeverityLevel;
    };

    libraryObjWrapper.setType = function(applicationType) {
        target.type = applicationType;
    };

    libraryObjWrapper.getType = function() {
        return target.type;
    };

    libraryObjWrapper.getVersion = function() {
        return target.version;
    };

    libraryObjWrapper.getCurrentPluginVersionObject = function() {
        var splittedPluginVersion = target.version.split("."),
                currentPluginVersion;

        currentPluginVersion = {
            major: parseInt(splittedPluginVersion[0], 10),
            minor: parseInt(splittedPluginVersion[1], 10),
            revision: parseInt(splittedPluginVersion[2], 10),
            build: parseInt(splittedPluginVersion[3], 10)
        };
        return currentPluginVersion;
    };

    return libraryObjWrapper;
};

var webRtcLibraryDecorator = function(target, _super) {
    return webRtcLibraryDecoratorImpl(target || {}, _super);
};

if (__testonly__) { __testonly__.webRtcLibraryDecorator = webRtcLibraryDecorator; }



var webRtcLibraryFirefoxDecoratorImpl = function(target, _super, _window, _navigator) {
    _super(target);

    target.getUserMedia = function(constraints, successCallback, failureCallback) {
        _navigator.mozGetUserMedia(constraints, successCallback, failureCallback);
    };

    target.showSettingsWindow = function() {
        return;
    };

    target.createRTCSessionDescription = function(type, sdp) {
        return new _window.mozRTCSessionDescription({"type": type, "sdp": sdp});
    };

    target.createRTCIceCandidate = function(candidate) {
        return  new _window.mozRTCIceCandidate(candidate);
    };

    target.getURLFromStream = function(stream) {
        return _window.URL.createObjectURL(stream);
    };

    target.createRTCPeerConnection = function(stunturn, constraints) {
        return new _window.mozRTCPeerConnection(stunturn, constraints);
    };

    target.checkMediaSourceAvailability = function(callback) {
        // Since _window.MediaStreamTrack.getSources or an equal method is not defined in Firefox Native,
        // sources set as true by default. This should be changed if method or workaround about getting sources provided.
        var videoSourceAvailable = true, audioSourceAvailable = true;
        utils.callFunctionIfExist(callback, {videoSourceAvailable: videoSourceAvailable,
            audioSourceAvailable: audioSourceAvailable});
    };

    target.get_audioInDeviceCount = function() {
        return 1;   // Use right method for Firefox Native
    };

    target.get_audioOutDeviceCount = function() {
        return 1;   // Use right method for Firefox Native
    };

    target.get_videoDeviceCount = function() {
        return 1;   // Use right method for Firefox Native
    };

    target.set_logSeverityLevel = function() {
        return false; // Not Applicable for Firefox Native
    };

    target.get_logSeverityLevel = function() {
        return; // Not Applicable for Firefox Native
    };
};

var webRtcLibraryFirefoxDecorator = function(target, _super, _window, _navigator) {
    webRtcLibraryFirefoxDecoratorImpl(target || {},
            _super || webRtcLibraryDecorator,
            _window || window,
            _navigator || navigator);
};

if (__testonly__) { __testonly__.webRtcLibraryFirefoxDecorator = webRtcLibraryFirefoxDecorator; }
var webRtcLibraryChromeDecoratorImpl = function(target, _super, _window, _navigator) {
    _super(target);

    target.getUserMedia = function(constraints, successCallback, failureCallback) {
        _navigator.webkitGetUserMedia(constraints, successCallback, failureCallback);
    };

    target.showSettingsWindow = function() {
        return;
    };

    target.createRTCSessionDescription = function(type, sdp) {
        return new _window.RTCSessionDescription({"type": type, "sdp": sdp});
    };

    target.createRTCIceCandidate = function(candidate) {
        return  new _window.RTCIceCandidate(candidate);
    };

    target.getURLFromStream = function(stream){
        return _window.URL.createObjectURL(stream);
    };

    target.createRTCPeerConnection = function(stunturn, constraints) {
        return new _window.webkitRTCPeerConnection(stunturn, constraints);
    };

    target.checkMediaSourceAvailability = function(callback) {
        var i, listOfNativeMediaStream, videoSourceAvailable, audioSourceAvailable;
        listOfNativeMediaStream = _window.MediaStreamTrack;
        if (typeof listOfNativeMediaStream !== 'undefined') {
            listOfNativeMediaStream.getSources(function(mediaSources) {
                for (i = 0; i < mediaSources.length; i++) {
                    if (mediaSources[i].kind === "video") {
                        // Video source is available such as webcam
                        videoSourceAvailable = true;
                    } else if (mediaSources[i].kind === "audio") {
                        // audio source is available such as mic
                        audioSourceAvailable = true;
                    }
                }
                utils.callFunctionIfExist(callback, {videoSourceAvailable: videoSourceAvailable,
                    audioSourceAvailable: audioSourceAvailable});
            });
        }
    };

    target.get_audioInDeviceCount = function() {
        return 1;   // Use right method for Chrome Native
    };

    target.get_audioOutDeviceCount = function() {
        return 1;   // Use right method for Chrome Native
    };

    target.get_videoDeviceCount = function() {
        return 1;   // Use right method for Chrome Native
    };

    target.set_logSeverityLevel = function() {
        return false; // Not Applicable for Chrome Native
    };

    target.get_logSeverityLevel = function() {
        return; // Not Applicable for Chrome Native
    };
};

var webRtcLibraryChromeDecorator = function(target, _super, _window, _navigator) {
    webRtcLibraryChromeDecoratorImpl(target || {},
            _super || webRtcLibraryDecorator,
            _window || window,
            _navigator || navigator);
};

if (__testonly__) { __testonly__.webRtcLibraryChromeDecorator = webRtcLibraryChromeDecorator; }
var WebRtcAdaptorImpl = function(_super, _decorator, _model, _logManager) {
    var self = this, logger = _logManager.getLogger("WebRtcAdaptorImpl");

    logger.debug('WebRtcAdaptor initializing');

    utils.compose(_model, self);

    /*
     * performNativeReconnectWorkaround - workaround to be used when IP interface changed
     */
    self.performReconnectWorkaround = function(call, onSuccess, onFailure) {
        var peer = call.peer, localSdp, localDescObj, localAudioDirection, localVideoDirection;

        logger.debug("performReconnectWorkaround:" + call.id);

        localSdp = sdpParser.deleteGoogleIceFromSdp(peer.localDescription.sdp);
        localAudioDirection = sdpParser.getAudioSdpDirection(localSdp);
        localVideoDirection = sdpParser.getVideoSdpDirection(localSdp);

        if (self.createNewPeerForCall(call))
        {
            peer = call.peer;
        }

        peer.createOffer(
                function prwCreateOfferSuccessCallback(oSdp) {
                    oSdp.sdp = sdpParser.updateAudioSdpDirection(oSdp.sdp, localAudioDirection);
                    oSdp.sdp = sdpParser.updateVideoSdpDirection(oSdp.sdp, localVideoDirection);

                    oSdp.sdp = sdpParser.deleteCryptoZeroFromSdp(oSdp.sdp);
                    oSdp.sdp = sdpParser.performVP8RTCPParameterWorkaround(oSdp.sdp);
                    oSdp.sdp = sdpParser.updateAudioCodec(oSdp.sdp);
                    oSdp.sdp = sdpParser.removeG722Codec(oSdp.sdp);
                    oSdp.sdp = sdpParser.deleteCryptoFromSdp(oSdp.sdp, self.isDtlsEnabled());
                    oSdp.sdp = sdpParser.setMediaActPass(oSdp.sdp, self.isDtlsEnabled());
                    oSdp.sdp = sdpParser.fixLocalTelephoneEventPayloadType(call, oSdp.sdp);
                    oSdp.sdp = sdpParser.replaceOpusCodec(oSdp.sdp);
                    oSdp.sdp = sdpParser.updateVersion(localSdp, oSdp.sdp);

                    localDescObj = self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.OFFER, oSdp.sdp);
                    peer.setLocalDescription(
                            localDescObj,
                            function prwSetLocalDescriptionSuccessCallback() {
                                logger.debug("performReconnectWorkaround: setLocalDescription success" + call.id);
                            },
                            function prwSetLocalDescriptionFailureCallback(e) {
                                logger.debug("performReconnectWorkaround: setLocalDescription failed!!" + e + call.id);
                                utils.callFunctionIfExist(onFailure);
                            });
                },
                function prwCreateOfferFailureCallback(e) {
                    logger.error("performReconnectWorkaround: createOffer failed!! " + e);
                    utils.callFunctionIfExist(onFailure);
                },
                {
                    'mandatory': {
                        'OfferToReceiveAudio': self.getMediaAudio(),
                        'OfferToReceiveVideo': self.getMediaVideo()
                    }
                });
    };

    // Native implementation lies on webRtcAdaptor.js
    self.getLocalAudioTrack = function(peer) {
        logger.debug("getLocalAudioTrack");
        var audioTracks;

        /*
         * ABE-832: On MAC OS, Safari browser version 6.1 doesn't recognize array
         * indices of integer type. Therefore, all [0] calls are changed to ["0"].
         * All other browser types function correctly with both integer and string
         * indices.
         */

        if(peer.localStreams && peer.localStreams["0"].audioTracks) {
            if (peer.localStreams["0"].audioTracks.length > 0) {
                return peer.localStreams["0"].audioTracks["0"];
            }
        }
        else if (peer.getLocalStreams) {
            audioTracks = peer.getLocalStreams()["0"].getAudioTracks();
            if(audioTracks && audioTracks.length > 0) {
                return audioTracks["0"];
            }
        }

        return null;
    };

    // Native implementation lies on webRtcAdaptor.js
    self.getLocalVideoTrack = function(peer) {
        logger.debug("getLocalVideoTrack");
        var streams;

        /*
         * ABE-832: On MAC OS, Safari browser version 6.1 doesn't recognize array
         * indices of integer type. Therefore, all [0] calls are changed to ["0"].
         * All other browser types function correctly with both integer and string
         * indices.
         */

        if(peer.localStreams && peer.localStreams["0"].videoTracks) {
            if (peer.localStreams["0"].videoTracks.length > 0) {
                return peer.localStreams["0"].videoTracks["0"];
            }
        }
        else if (peer.getLocalStreams) {
            streams = peer.getLocalStreams();
            if(streams && streams["0"].getVideoTracks() && streams["0"].getVideoTracks().length > 0) {
                return streams["0"].getVideoTracks()["0"];
            }
        }

        return null;
    };

    /*
     * Native implementation lies on webRtcAdaptor.js
     * Mutes audio and video tracks (to be used during Hold)
     *
     * @ignore
     * @name rtc.mute
     * @function
     * @param {Object} call internalCall
     * @param {boolean} mute true to mute, false to unmute
     */
    self.muteOnHold = function(call, mute) {
        var localAudioTrack, localVideoTrack;

        logger.info("Mute on Hold called, mute=" + mute);
        if (!self.isInitialized()) {
            logger.warn("Plugin is not installed");
            return;
        }

        if (!call.peer) {
            return;
        }

        localAudioTrack = self.getLocalAudioTrack(call.peer);
        if (localAudioTrack) {
            localAudioTrack.enabled = !mute;
            call.audioMuted = mute;
        }

        localVideoTrack = self.getLocalVideoTrack(call.peer);
        if (localVideoTrack) {
            localVideoTrack.enabled = !mute;
            call.videoMuted = mute;
        }
    };

    /*
     * Native implementation lies on webRtcAdaptor.js
     * performNativeOrigAudioWorkaround - orig side can't hear audio when term side didn't start with video
     */
    self.performOrigAudioWorkaround = function(call, onSuccess, onFail) {
        logger.debug("Workaround for orig side to hear audio");

        call.sdp = sdpParser.setMediaPassive(call.sdp, self.isDtlsEnabled());

        call.peer.setRemoteDescription(
                self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.ANSWER, call.sdp), function() {
            logger.debug("performNativeOrigAudioWorkaround: setRemoteDescription success");
            utils.callFunctionIfExist(onSuccess);
        }, function(e) {
            logger.debug("performNativeOrigAudioWorkaround: setRemoteDescription failed: " + e);
            utils.callFunctionIfExist(onFail);
        });
    };

    /*
     * Native implementation lies on webRtcAdaptor.js
     * restoreActualSdp - local and remote sdp's were manipulated to play audio. restore them here.
     */
    self.restoreActualSdp = function(call, onSuccess, onFail, localVideoDirection, remoteVideoDirection) {
        logger.debug("Restore manipulated local and remote sdp's");
        var newLocalSdp = call.peer.localDescription.sdp;
        newLocalSdp = sdpParser.updateSdpDirection(newLocalSdp, CONSTANTS.STRING.VIDEO, localVideoDirection);

        newLocalSdp = sdpParser.setMediaActPass(newLocalSdp, self.isDtlsEnabled());
        call.sdp = sdpParser.setMediaPassive(call.sdp, self.isDtlsEnabled());

        newLocalSdp = sdpParser.fixLocalTelephoneEventPayloadType(call, newLocalSdp);

        // set local sdp with original direction
        call.peer.setLocalDescription(
                self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.OFFER, newLocalSdp), function() {
            logger.debug("restoreNativeActualSdp: setLocalDescription success");
            // restore actual remote sdp
            call.sdp = sdpParser.changeDirection(call.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_ONLY, remoteVideoDirection, CONSTANTS.STRING.VIDEO);
            call.sdp = sdpParser.changeDirection(call.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_ONLY, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE, CONSTANTS.STRING.VIDEO);

            // this is required just before setRemoteDescription
            webRtcAdaptorUtils.callSetReceiveVideo(call);

            call.peer.setRemoteDescription(
                    self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.ANSWER, call.sdp), function() {
                logger.debug("restoreNativeActualSdp: setRemoteDescription success");
                utils.callFunctionIfExist(onSuccess);
            }, function(e) {
                logger.debug("restoreNativeActualSdp: setRemoteDescription failed: " + e);
                utils.callFunctionIfExist(onFail);
            });
        }, function(e) {
            logger.debug("restoreNativeActualSdp: setLocalDescription failed: " + e);
            utils.callFunctionIfExist(onFail);
        });
    };

    // Native implementation lies on webRtcAdaptor.js
    self.setMediaSources = function(mediaSourceInfo) {
        if (mediaSourceInfo) {
            self.setVideoSourceAvailable(mediaSourceInfo.videoSourceAvailable);
            self.setAudioSourceAvailable(mediaSourceInfo.audioSourceAvailable);
        }
    };
    // Native implementation lies on webRtcAdaptor.js
    // initNativeMedia
    self.initMedia = function(onSuccess, onFailure, options) {
        self.setInitialized(true);
        _decorator(self.getRtcLibrary());
        self.getRtcLibrary().checkMediaSourceAvailability(function mediaSourceCallback(mediaSourceInfo) {
            self.setMediaSources(mediaSourceInfo);
        });

        if(options) {
            if (options.localVideoContainer) {
                self.setLocalVideoContainer(options.localVideoContainer);
            }

            if (options.remoteVideoContainer) {
                self.setRemoteVideoContainer(options.remoteVideoContainer);
            }

            if (options.videoContainer) {
                self.setDefaultVideoContainer(options.videoContainer);
            }
        }

        onSuccess();
    };

    /*
     * Native implementation lies on webRtcAdaptor.js
     * Add Candidates
     * @ignore
     * @param {type} call
     */
    self.addCandidates = function(call) {
        var ma_indx, mv_indx, ma_str = "", mv_str = "", c_indx, candidate, arr, i, reg = /\r\n|\r|\n/;

        ma_indx = call.sdp.indexOf(CONSTANTS.SDP.M_LINE + CONSTANTS.STRING.AUDIO, 0);
        mv_indx = call.sdp.indexOf(CONSTANTS.SDP.M_LINE + CONSTANTS.STRING.VIDEO, 0);

        if(ma_indx !== -1 && mv_indx !== -1) {
            if(ma_indx < mv_indx) {
                ma_str = call.sdp.substring(ma_indx, mv_indx);
                mv_str = call.sdp.substring(mv_indx);
            } else {
                mv_str = call.sdp.substring(mv_indx, ma_indx);
                ma_str = call.sdp.substring(ma_indx);
            }
        } else if(ma_indx !== -1) {
            ma_str = call.sdp.substring(ma_indx);
        } else if(mv_indx !== -1) {
            mv_str = call.sdp.substring(mv_indx);
        }

        if (ma_str !== "") {
            c_indx = ma_str.indexOf("a=candidate", 0);
            if (c_indx !== -1) {
                ma_str = ma_str.substring(c_indx);
                arr = ma_str.split(reg);
                i = 0;
                while (arr[i] && arr[i].indexOf("a=candidate") !== -1) {
                    candidate = self.getRtcLibrary().createRTCIceCandidate({sdpMLineIndex: 0, candidate: arr[i]});
                    call.peer.addIceCandidate(candidate);
                    i++;
                }
            }
        }

        if (mv_str !== "") {
            c_indx = mv_str.indexOf("a=candidate", 0);
            if (c_indx !== -1) {
                mv_str = mv_str.substring(c_indx);
                arr = mv_str.split(reg);
                i = 0;
                while (arr[i] && arr[i].indexOf("a=candidate") !== -1) {
                    candidate = self.getRtcLibrary().createRTCIceCandidate({sdpMLineIndex: 1, candidate: arr[i]});
                    call.peer.addIceCandidate(candidate);
                    i++;
                }

            }
        }
    };

    /*
     * Native implementation lies on webRtcAdaptor.js
     * performNativeVideoStartWorkaround - term side cannot see orig's video
     */
    self.performVideoStartWorkaround = function(call, onSuccess, onFail) {
        var peer = call.peer, remoteAudioState, remoteVideoState, callSdpWithNoSsrc;

        logger.debug("Workaround to play video");

        call.sdp = sdpParser.addSdpMissingCryptoLine(call.sdp);

        remoteAudioState = sdpParser.getAudioSdpDirection(call.sdp);
        remoteVideoState = sdpParser.getVideoSdpDirection(call.sdp);

        call.sdp = sdpParser.updateAudioSdpDirectionToInactive(call.sdp);
        call.sdp = sdpParser.updateVideoSdpDirectionToInactive(call.sdp);

        call.sdp = sdpParser.setMediaActPass(call.sdp, self.isDtlsEnabled());

        // In Peer-Peer call, in order to remove remote stream properly,
        // ssrc lines should be deleted so that workaround below will
        // first remove the remote stream and then re-add it according to
        // actuall call sdp.
        // In Non Peer-Peer call, ther is no ssrc line in sdp so it is safe
        // to keep method below.
        callSdpWithNoSsrc = sdpParser.deleteSsrcFromSdp(call.sdp);

        peer.setRemoteDescription(
                self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.OFFER, callSdpWithNoSsrc),
                function pvswFirstSetRemoteDescriptionSuccessCallback() {
                    logger.debug("performVideoStartWorkaround: first setRemoteDescription success");

                    // restore original values
                    call.sdp = sdpParser.updateAudioSdpDirection(call.sdp, remoteAudioState);
                    call.sdp = sdpParser.updateVideoSdpDirection(call.sdp, remoteVideoState);

                    peer.setRemoteDescription(
                            self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.OFFER, call.sdp),
                            function pvswSecondSetRemoteDescriptionSuccessCallback() {
                                logger.debug("performVideoStartWorkaround: second setRemoteDescription success");
                                peer.createAnswer(
                                        function pvswCreateAnswerSuccessCallback(obj) {
                                            if (remoteAudioState === CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE) {
                                                obj.sdp = sdpParser.updateAudioSdpDirectionToInactive(obj.sdp);
                                            }

                                            if (remoteVideoState === CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE) {
                                                obj.sdp = sdpParser.updateVideoSdpDirectionToInactive(obj.sdp);
                                            } else if (webRtcAdaptorUtils.callCanLocalSendVideo(call)) {
                                                obj.sdp = sdpParser.updateVideoSdpDirection(obj.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE);
                                            } else {
                                                obj.sdp = sdpParser.updateVideoSdpDirection(obj.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY);
                                            }

                                            obj.sdp = sdpParser.performVP8RTCPParameterWorkaround(obj.sdp);
                                            self.fireOnStreamAddedEvent(call);

                                            obj.sdp = sdpParser.checkAndRestoreICEParams(obj.sdp, call.sdp);

                                            obj.sdp = sdpParser.setMediaPassive(obj.sdp, self.isDtlsEnabled());

                                            obj.sdp = sdpParser.fixLocalTelephoneEventPayloadType(call, obj.sdp);

                                            peer.setLocalDescription(
                                                    self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.ANSWER, obj.sdp),
                                                    function pvswSetLocalDescriptionSuccessCallback() {
                                                        logger.debug("performVideoStartWorkaround: setlocalDescription success");
                                                        utils.callFunctionIfExist(onSuccess);
                                                    },
                                                    function pvswSetLocalDescriptionFailureCallback(e) {
                                                        logger.debug("performVideoStartWorkaround: setlocalDescription failed!!" + e);
                                                        utils.callFunctionIfExist(onFail, "performVideoStartWorkaround: setlocalDescription failed!!");
                                                    });
                                        },
                                        function pvswCreateAnswerFailureCallback(e) {
                                            logger.debug("performVideoStartWorkaround: createAnswer failed!! " + e);
                                            utils.callFunctionIfExist(onFail, "Session cannot be created");
                                        },
                                        {
                                            'mandatory': {
                                                'OfferToReceiveAudio': self.getMediaAudio(),
                                                'OfferToReceiveVideo': self.getMediaVideo()
                                            }
                                        });
                            },
                            function pvswSecondSetRemoteDescriptionFailureCallback(e) {
                                logger.debug("performVideoStartWorkaround: second setRemoteDescription failed!!" + e);
                                utils.callFunctionIfExist(onFail, "performVideoStartWorkaround: second setRemoteDescription failed!!");
                            });
                },
                function pvswFirstSetRemoteDescriptionFailureCallback(e) {
                    logger.debug("performVideoStartWorkaround: first setRemoteDescription failed!!" + e);
                    utils.callFunctionIfExist(onFail, "performVideoStartWorkaround: first setRemoteDescription failed!!");
                });
    };

    /*
     * Native implementation lies on webRtcAdaptor.js
     */
    self.getUserMedia = function(onSuccess, onFailure) {
        self.getRtcLibrary().checkMediaSourceAvailability(function mediaSourceCallback(mediaSourceInfo) {
            var video_constraints;
            self.setMediaSources(mediaSourceInfo);
            if (self.getMediaVideo() && self.getVideoSourceAvailable()) {
                video_constraints = {
                    mandatory: {
                        //"minFrameRate": "30",
                        "maxWidth": self.getVideoWidth(),
                        "maxHeight": self.getVideoHeight(),
                        "minWidth": self.getVideoWidth(),
                        "minHeight": self.getVideoHeight()}
                };
            } else {
                video_constraints = false;
            }

            self.getRtcLibrary().getUserMedia({
                audio: self.getMediaAudio(),
                video: video_constraints
            }, function getUserMediaSuccessCallback(stream) {
                var mediaInfo;
                logger.debug("user has granted access to local media.");
                self.setLocalStream(stream);

                self.setInitialized(true);
                mediaInfo = {
                    "audio": self.getMediaAudio(),
                    "video": self.getMediaVideo()
                };
                utils.callFunctionIfExist(onSuccess, mediaInfo);
            }, function getUserMediaFailureCallback(error) {
                logger.debug("Failed to get access to local media. Error code was " + error.code);
                utils.callFunctionIfExist(onFailure, fcs.call.MediaErrors.NOT_ALLOWED);
            });
        });
    };

    // createNativeOffer, Native implementation lies on webRtcAdaptor.js
    self.createOffer = function (call, successCallback, failureCallback, sendInitialVideo) {
        logger.debug("createOffer: sendInitialVideo= " + sendInitialVideo + " state= " + call.peer.signalingState);
        var peer = call.peer;

        peer.addStream(self.getLocalStream());
        call.localStream = self.getLocalStream();

        peer.createOffer(
                function createOfferSuccessCallback(oSdp) {
                    sendInitialVideo = sendInitialVideo && self.getVideoSourceAvailable();
                    if (sendInitialVideo) {
                        oSdp.sdp = sdpParser.updateVideoSdpDirection(oSdp.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE);
                    } else {
                        oSdp.sdp = sdpParser.updateVideoSdpDirection(oSdp.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY);
                    }

                    oSdp.sdp = sdpParser.deleteCryptoZeroFromSdp(oSdp.sdp);

                    oSdp.sdp = sdpParser.performVP8RTCPParameterWorkaround(oSdp.sdp);
                    oSdp.sdp = sdpParser.updateAudioCodec(oSdp.sdp);
                    oSdp.sdp = sdpParser.removeG722Codec(oSdp.sdp);

                    oSdp.sdp = sdpParser.deleteCryptoFromSdp(oSdp.sdp, self.isDtlsEnabled());
                    oSdp.sdp = sdpParser.setMediaActPass(oSdp.sdp, self.isDtlsEnabled());

                    oSdp.sdp = sdpParser.fixLocalTelephoneEventPayloadType(call, oSdp.sdp);
                    oSdp.sdp = sdpParser.replaceOpusCodec(oSdp.sdp);

                    peer.setLocalDescription(
                            self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.OFFER, oSdp.sdp),
                            function createOfferSetLocalDescriptionSuccessCallback() {
                                //Due to stun requests, successCallback will be called by onNativeIceCandidate()
                                webRtcAdaptorUtils.setLocalStreamVideoSendStatus(call, sendInitialVideo);
                            }
                    , function createOfferSetLocalDescriptionFailureCallback(error) {
                        logger.error("createOffer: setLocalDescription failed : " + error);
                        utils.callFunctionIfExist(failureCallback, "createOffer: setLocalDescription failed");
                    });
                }, function createOfferFailureCallback(e) {
            logger.error("createOffer: createOffer failed!! " + e);
            utils.callFunctionIfExist(failureCallback);
        },
                {
                    'mandatory': {
                        'OfferToReceiveAudio': self.getMediaAudio(),
                        'OfferToReceiveVideo': self.getMediaVideo()
                    }
                });
    };

    /**
     *  Native implementation lies on webRtcAdaptor.js
     *  createNativeAnswer to be used when native webrtc is enabled.
     *  @param {type} call
     *  @param {type} successCallback
     *  @param {type} failureCallback
     *  @param {type} isVideoEnabled
     */
    self.createAnswer = function(call, successCallback, failureCallback, isVideoEnabled) {
        logger.debug("createAnswer: isVideoEnabled= " + isVideoEnabled + " state= " + call.peer.signalingState);
        var peer = call.peer;

        peer.addStream(self.getLocalStream());
        call.localStream = self.getLocalStream();
        call.sdp = sdpParser.removeG722Codec(call.sdp);
        call.sdp = sdpParser.performG722ParameterWorkaround(call.sdp);
        call.sdp = sdpParser.performVP8RTCPParameterWorkaround(call.sdp);
        call.sdp = sdpParser.checkSupportedVideoCodecs(call.sdp, null);
        call.sdp = sdpParser.fixRemoteTelephoneEventPayloadType(call, call.sdp);
        call.sdp = sdpParser.changeDirection(call.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE, CONSTANTS.STRING.AUDIO);
        call.sdp = sdpParser.setMediaActPass(call.sdp, self.isDtlsEnabled());
        call.sdp = sdpParser.deleteFingerprintOrCrypto(call.sdp, self.isDtlsEnabled());

        if (!sdpParser.isSdpVideoSendEnabled(call.sdp)) {
            // delete ssrc only from video, keep audio ssrc to hear audio
            call.sdp = sdpParser.deleteInactiveVideoSsrc(call.sdp);
        }
        peer.setRemoteDescription(
                self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.OFFER, call.sdp),
            function createAnswerSetRemoteDescriptionSuccessCallback(){
                    webRtcAdaptorUtils.callSetReceiveVideo(call);
                    self.addCandidates(call);
                    call.remoteVideoState = sdpParser.getSdpDirection(call.sdp, CONSTANTS.STRING.VIDEO);

                    peer.createAnswer(
                            function(oSdp) {
                                isVideoEnabled = isVideoEnabled && self.getVideoSourceAvailable() && sdpParser.isSdpHasVideo(call.sdp);
                                webRtcAdaptorUtils.setLocalStreamVideoSendStatus(call, isVideoEnabled);

                                if (isVideoEnabled) {
                                    if (sdpParser.isSdpVideoSendEnabled(call.sdp)) {
                                        oSdp.sdp = sdpParser.updateSdpDirection(oSdp.sdp, CONSTANTS.STRING.VIDEO, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE);
                                    } else {
                                        oSdp.sdp = sdpParser.updateSdpDirection(oSdp.sdp, CONSTANTS.STRING.VIDEO, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_ONLY);
                                    }
                                } else {
                                    if (sdpParser.isSdpVideoSendEnabled(call.sdp)) {
                                        oSdp.sdp = sdpParser.updateSdpDirection(oSdp.sdp, CONSTANTS.STRING.VIDEO, CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY);
                                    } else {
                                        oSdp.sdp = sdpParser.updateSdpDirection(oSdp.sdp, CONSTANTS.STRING.VIDEO, CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE);
                                    }
                                }

                                oSdp.sdp = sdpParser.performVP8RTCPParameterWorkaround(oSdp.sdp);
                                self.muteOnHold(call, false);

                                oSdp.sdp = sdpParser.setMediaPassive(oSdp.sdp, self.isDtlsEnabled());

                                oSdp.sdp = sdpParser.fixLocalTelephoneEventPayloadType(call, oSdp.sdp);

                                peer.setLocalDescription(
                                        self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.ANSWER, oSdp.sdp),
                                        function createAnswerSetLocalDescriptionSuccessCallback(){
                                            //Due to stun requests, successCallback will be called by onNativeIceCandidate()
                                            call.videoOfferSent = sdpParser.isSdpHasVideo(oSdp.sdp);
                                        },
                                        function createAnswerSetLocalDescriptionFailureCallback(e) {
                                            logger.error("createAnswer: setLocalDescription failed : " + e);
                                            utils.callFunctionIfExist(failureCallback, "createNativeAnswer setLocalDescription failed");
                                        });
                            },
                            function createAnswerFailureCallback(e){
                                logger.error("createAnswer: failed!! Error: " + e);
                                utils.callFunctionIfExist(failureCallback, "Session cannot be created");
                            },
                            {
                                'mandatory': {
                                    'OfferToReceiveAudio': self.getMediaAudio(),
                                    'OfferToReceiveVideo': self.getMediaVideo()
                                }
                            });
                },
                function createAnswerSetRemoteDescriptionFailureCallback(e){
                    logger.error("createAnswer: setremotedescription failed!! Error: " + e);
                });
    };

    /*
     * Native implementation lies on webRtcAdaptor.js
     * createNativeUpdate to be used when the video start or stop
     */
    self.createUpdate = function(call, successCallback, failureCallback, isVideoStart) {
        logger.debug("createUpdate: isVideoStart= " + isVideoStart + " state= " + call.peer.signalingState);
        var localSdp, isIceLite;

        call.stableRemoteSdp = call.peer.remoteDescription.sdp;
        call.stableLocalSdp = call.peer.localDescription.sdp;

        localSdp = call.peer.localDescription.sdp;
        isIceLite = call.isIceLite;
        localSdp = sdpParser.fixLocalTelephoneEventPayloadType(call, localSdp);
        localSdp = sdpParser.incrementVersion(localSdp);
        localSdp = sdpParser.setMediaActPass(localSdp, self.isDtlsEnabled());
        webRtcAdaptorUtils.setLocalStreamVideoSendStatus(call, isVideoStart);

        // for ice-lite scenario:
        // if there is no video m-line in the localSdp, create new offer to start the video
        // if there is video m-line and video is allocated for the first time, only replace the stream
        // for peer-to-peer scenario:
        // if video is allocated for the first time, create new offer

        if (isIceLite) {
            if (sdpParser.isSdpHasVideo(localSdp)) {
                self.createUpdateWithSetLocalDescription(call, successCallback, failureCallback, isVideoStart, localSdp);
            } else {
                self.createUpdateWithCreateOffer(call, successCallback, failureCallback, isVideoStart, localSdp, isIceLite);
            }
        } else {
            if (call.videoOfferSent) {
                self.createUpdateWithSetLocalDescription(call, successCallback, failureCallback, isVideoStart, localSdp);
            } else {
                self.createUpdateWithCreateOffer(call, successCallback, failureCallback, isVideoStart, localSdp, isIceLite);
            }
        }
    };

    /*
     * Reverts RTC engine's state
     */
    self.revertRtcState = function(call, successCallback, failureCallback) {
        var peer = call.peer, obj, localSdp = call.stableLocalSdp,
                remoteSdp = call.stableRemoteSdp,
                rtcState = peer.signalingState;
        remoteSdp = sdpParser.deleteGoogleIceFromSdp(remoteSdp);
        switch (rtcState) {
            case CONSTANTS.WEBRTC.RTC_SIGNALING_STATE.STABLE:
            case CONSTANTS.WEBRTC.RTC_SIGNALING_STATE.HAVE_LOCAL_OFFER:
                localSdp = sdpParser.setMediaActPass(localSdp, self.isDtlsEnabled());
                obj = self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.OFFER, localSdp);
                peer.setLocalDescription(obj,
                        function revertRtcStateLocalDescriptionSuccessCallback() {
                            logger.debug("revertRtcState[stable|local_offer]: setLocalDescription success");
                            remoteSdp = sdpParser.setMediaPassive(remoteSdp, self.isDtlsEnabled());
                            obj = self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.ANSWER, remoteSdp);
                            peer.setRemoteDescription(obj,
                                    function revertRtcStateRemoteDescriptionSuccessCallback() {
                                        logger.debug("revertRtcState[stable|local_offer]: setRemoteDescription success");
                                        utils.callFunctionIfExist(successCallback, call);
                                    }, function revertRtcStateRemoteDescriptionFailureCallback(error) {
                                        logger.error("revertRtcState[stable|local_offer]: setRemoteDescription failed: " + error);
                                        utils.callFunctionIfExist(failureCallback, call);
                            });
                        },
                        function revertRtcStateLocalDescriptionFailureCallback(error) {
                            logger.error("revertRtcState[stable|local_offer]: setLocalDescription failed: " + error);
                            utils.callFunctionIfExist(failureCallback, call);
                        });
                break;
            case CONSTANTS.WEBRTC.RTC_SIGNALING_STATE.HAVE_REMOTE_OFFER:
                remoteSdp = sdpParser.setMediaActPass(remoteSdp, self.isDtlsEnabled());
                obj = self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.OFFER, remoteSdp);
                peer.setRemoteDescription(obj,
                        function revertRtcStateRemoteDescriptionSuccessCallback() {
                            logger.debug("revertRtcState[remote_offer]: setLocalDescription success");
                            localSdp = sdpParser.setMediaPassive(localSdp, self.isDtlsEnabled());
                            obj = self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.ANSWER, localSdp);
                            peer.setLocalDescription(obj,
                                    function revertRtcStateLocalDescriptionSuccessCallback() {
                                        logger.debug("revertRtcState[remote_offer]: setRemoteDescription success");
                                        utils.callFunctionIfExist(successCallback, call);
                                    }, function revertRtcStateLocalDescriptionFailureCallback(error) {
                                logger.error("revertRtcState[remote_offer]: setRemoteDescription failed: " + error);
                                utils.callFunctionIfExist(failureCallback, call);
                            });
                        },
                        function revertRtcStateRemoteDescriptionFailureCallback(error) {
                            logger.error("revertRtcState[remote_offer]: setLocalDescription failed: " + error);
                            utils.callFunctionIfExist(failureCallback, call);
                        });
                break;
            default:
                logger.debug("revertRtcState: not applicible for state: " + rtcState);
        }
    };

    /*
     * Native implementation lies on webRtcAdaptor.js
     * createNativeHoldUpdate to be used when native webrtc is enabled
     */
    self.createHoldUpdate = function(call, hold, remote_hold_status, successCallback, failureCallback) {
        logger.debug("createHoldUpdate: local hold= " + hold + " remote hold= " + remote_hold_status + " state= " + call.peer.signalingState);
        var peer = call.peer,
                audioDirection,
                videoDirection,
                localSdp,
                externalSdp,
                tempSdp,
                muteCall,
                obj;

        call.stableRemoteSdp = peer.remoteDescription.sdp;
        call.stableLocalSdp = peer.localDescription.sdp;

        tempSdp = sdpParser.incrementVersion(call.peer.localDescription.sdp);

        tempSdp = sdpParser.setMediaActPass(tempSdp, self.isDtlsEnabled());

        //two sdp-s are created here
        //one is to be used by rest-request (externalSdp)
        //one is to set the audio-video direction of the local call (localSdp)
        //this is needed in order to adapt to the rfc (needs sendrecv to sendonly transition)
        //and to the plugin (needs inactive to mute audio and video connection)
        externalSdp = tempSdp;
        localSdp = tempSdp;

        if(hold || remote_hold_status){
            audioDirection = sdpParser.getAudioSdpDirection(externalSdp);
            if (audioDirection === CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE) {
                externalSdp = sdpParser.updateAudioSdpDirection(externalSdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_ONLY);
            } else {
                if (!hold && remote_hold_status) {
                    externalSdp = sdpParser.updateAudioSdpDirection(externalSdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE);
                } else {
                    externalSdp = sdpParser.updateAudioSdpDirectionToInactive(externalSdp);
                }
            }
            videoDirection = sdpParser.getVideoSdpDirection(externalSdp);
            if (videoDirection === CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE) {
                externalSdp = sdpParser.updateVideoSdpDirection(externalSdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_ONLY);
            } else {
                if (!hold && remote_hold_status) {
                    externalSdp = sdpParser.updateVideoSdpDirection(externalSdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE);
                } else {
                    externalSdp = sdpParser.updateVideoSdpDirectionToInactive(externalSdp);
                }
            }
            localSdp = sdpParser.updateAudioSdpDirectionToInactive(externalSdp);
            localSdp = sdpParser.updateVideoSdpDirectionToInactive(localSdp);
            muteCall = true;
        } else {
            externalSdp = sdpParser.updateAudioSdpDirection(externalSdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE);
            if (webRtcAdaptorUtils.callCanLocalSendVideo(call)) {
                externalSdp = sdpParser.updateVideoSdpDirection(externalSdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE);
            } else {
                externalSdp = sdpParser.updateVideoSdpDirection(externalSdp, CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY);
            }

            localSdp = externalSdp;
            muteCall = false;
        }

        localSdp = sdpParser.fixLocalTelephoneEventPayloadType(call, localSdp);

        obj = self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.OFFER, localSdp);

        peer.setLocalDescription(obj,
                function createHoldUpdateSetLocalDescriptionSuccessCallback() {
                    logger.debug("createHoldUpdate: setLocalDescription success");
                    self.muteOnHold(call, muteCall);
                    utils.callFunctionIfExist(successCallback, externalSdp);
                },
                function createHoldUpdateSetLocalDescriptionFailureCallback(error){
                    logger.error("createHoldUpdate: setLocalDescription failed: " + error);
                    utils.callFunctionIfExist(failureCallback);
                });
    };

    self.createReOffer = function(call, successCallback, failureCallback, iceRestart) {
        var peer = call.peer, offerSdp;
        peer.createOffer(
                function processSlowStartCreateOfferSuccessCallback(oSdp) {
                    oSdp.sdp = sdpParser.deleteCryptoZeroFromSdp(oSdp.sdp);
                    oSdp.sdp = sdpParser.performVP8RTCPParameterWorkaround(oSdp.sdp);
                    oSdp.sdp = sdpParser.updateAudioCodec(oSdp.sdp);
                    oSdp.sdp = sdpParser.removeG722Codec(oSdp.sdp);
                    oSdp.sdp = sdpParser.deleteCryptoFromSdp(oSdp.sdp, self.isDtlsEnabled());
                    oSdp.sdp = sdpParser.setMediaActPass(oSdp.sdp, self.isDtlsEnabled());
                    oSdp.sdp = sdpParser.fixLocalTelephoneEventPayloadType(call, oSdp.sdp);
                    oSdp.sdp = sdpParser.replaceOpusCodec(oSdp.sdp);

                    offerSdp = self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.OFFER, oSdp.sdp);
                    peer.setLocalDescription(
                            offerSdp,
                            function processSlowStartSetLocalDescriptionSuccessCallback() {
                                logger.debug("create ReOffer setLocalDescription success");
                                if (sdpParser.isMediaPortReady(oSdp.sdp)) {
                                    utils.callFunctionIfExist(successCallback, oSdp.sdp);
                                    call.successCallback = null;
                                }
                            },
                            function processSlowStartSetLocalDescriptionFailureCallback(error) {
                                utils.callFunctionIfExist(failureCallback, "create ReOffer setLocalDescription failed: " + error);
                            });
                },
                function processSlowStartCreateOfferFailureCallback(error) {
                    logger.error("create ReOffer failed!! " + error);
                    utils.callFunctionIfExist(failureCallback);
                },
                {
                    'mandatory': {
                        'OfferToReceiveAudio': self.getMediaAudio(),
                        'OfferToReceiveVideo': self.getMediaVideo(),
                        'IceRestart': iceRestart
                    }
                });
    };

    // Native implementation lies on webRtcAdaptor.js
    // processNativeHold
    self.processHold = function(call, hold, local_hold_status, successCallback, failureCallback) {
        logger.debug("processHold: local hold= " + local_hold_status + " remote hold= " + hold + " state= " + call.peer.signalingState);
        var peer = call.peer, updateSdp, audioDirection, videoDirection,
                peerRemoteSdp, peerLocalSdp, inactiveRemoteSdp, newPeerCreated = false;

        call.stableRemoteSdp = peer.remoteDescription.sdp;
        call.stableLocalSdp = peer.localDescription.sdp;

        if (!local_hold_status && !hold) {
            self.muteOnHold(call, false);
        }

        call.sdp = sdpParser.checkSupportedVideoCodecs(call.sdp, null);
        call.sdp = sdpParser.performVideoPortZeroWorkaround(call.sdp);
        call.sdp = sdpParser.checkAndRestoreICEParams(call.sdp, call.peer.localDescription.sdp);
        call.sdp = sdpParser.removeG722Codec(call.sdp);
        call.sdp = sdpParser.performG722ParameterWorkaround(call.sdp);
        call.sdp = sdpParser.performVP8RTCPParameterWorkaround(call.sdp);
        call.sdp = sdpParser.fixRemoteTelephoneEventPayloadType(call, call.sdp);
        call.sdp = sdpParser.performVP8BandwidthWorkaround(call.sdp);

        call.sdp = sdpParser.setMediaActPass(call.sdp, self.isDtlsEnabled());

        // is this necessary?, if so below code should be revised,
        // it will not change directions in the sdp
//        if (!sdpParser.isSdpContainsAudioDirection(call.sdp) &&
//                !sdpParser.isSdpContainsVideoDirection(call.sdp)) {
//            if (hold || local_hold_status) {
//                logger.debug("processHold: call.sdp has no direction so setting as inactive for " + (hold ? "remote hold" : "remote unhold with local hold"));
//                call.sdp = sdpParser.updateAudioSdpDirectionToInactive(call.sdp);
//                call.sdp = sdpParser.updateVideoSdpDirectionToInactive(call.sdp);
//            } else {
//                logger.debug("processHold: call.sdp has no direction so setting as sendrecv for unhold");
//                call.sdp = sdpParser.updateAudioSdpDirection(call.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE);
//                call.sdp = sdpParser.updateVideoSdpDirection(call.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE);
//            }
//        }

        audioDirection = sdpParser.getAudioSdpDirection(call.sdp);
        videoDirection = sdpParser.getVideoSdpDirection(call.sdp);

        peerRemoteSdp = call.prevRemoteSdp;
        peerLocalSdp = peer.localDescription.sdp;
        updateSdp = self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.OFFER, call.sdp);
        inactiveRemoteSdp = self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.OFFER, updateSdp.sdp);

        inactiveRemoteSdp.sdp = sdpParser.updateAudioSdpDirectionToInactive(inactiveRemoteSdp.sdp); // chrome38 fix
        inactiveRemoteSdp.sdp = sdpParser.updateVideoSdpDirectionToInactive(inactiveRemoteSdp.sdp); // chrome38 fix

        //call.sdp is given because of plugin crash
        if (self.createNewPeerForCallIfIceChangedInRemoteSdp(call, call.sdp, peerRemoteSdp)) {
            peer = call.peer;
            newPeerCreated = true;
        }
        inactiveRemoteSdp.sdp = sdpParser.deleteSsrcFromSdp(inactiveRemoteSdp.sdp);

        // 1st setRemoteDescription to make webrtc remove the audio and/or video streams
        // 2nd setRemote will add the audio stream back so that services like MOH can work
        // This code will also run in UnHold scenario, and it will remove & add video stream
        peer.setRemoteDescription(
                inactiveRemoteSdp,
                function processHoldSetFirstRemoteDescriptionSuccessCallback() {
                    updateSdp.sdp = sdpParser.updateAudioSdpDirection(updateSdp.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE);
                    //updateSdp.sdp = updateSdpDirection(updateSdp.sdp, video, videoDirection);

                    if (sdpParser.getVideoSdpDirection(updateSdp.sdp) === CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE ||
                            sdpParser.getVideoSdpDirection(updateSdp.sdp) === CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY)
                    {
                        updateSdp.sdp = sdpParser.deleteInactiveVideoSsrc(updateSdp.sdp);
                    }
                    peer.setRemoteDescription(
                            updateSdp,
                            function processHoldSetSecondRemoteDescriptionSuccessCallback() {
                                if (!hold && !local_hold_status && (videoDirection === CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE)) {
                                    call.remoteVideoState = CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY;
                                } else{
                                    call.remoteVideoState = sdpParser.getVideoSdpDirection(updateSdp.sdp);
                                }
                                //check if remote party sends video
                                webRtcAdaptorUtils.callSetReceiveVideo(call);
                                peer.createAnswer(
                                    function processHoldCreateAnswerSuccessCallback(obj){
                                            logger.debug("processHold: isSdpEnabled audio= " + sdpParser.isAudioSdpEnabled(obj.sdp));
                                            logger.debug("processHold: isSdpEnabled video= " + sdpParser.isVideoSdpEnabled(obj.sdp));

                                            if (hold) {
                                                logger.debug("processHold: Remote HOLD");

                                                obj.sdp = sdpParser.respondToRemoteSdpDirections(obj.sdp, call.sdp);

                                                // is this necessary?, if so below code should be revised,
                                                // it will not change directions in the sdp
//                                if ((sr_indx + 1) + (so_indx + 1) + (ro_indx + 1) + (in_indx + 1) === 0) {
//                                    logger.debug("processNativeHold: no direction detected so setting as inactive");
//                                    obj.sdp = updateSdpDirection(obj.sdp, audio, MediaStates.INACTIVE);
//                                    obj.sdp = updateSdpDirection(obj.sdp, video, MediaStates.INACTIVE);
//                                }
                                            } else if (!local_hold_status) {
                                                logger.debug("processHold: Remote UNHOLD: direction left as it is");

                                                if (webRtcAdaptorUtils.callCanLocalSendVideo(call)) {
                                                    if (sdpParser.isSdpVideoSendEnabled(call.sdp)) {
                                                        obj.sdp = sdpParser.updateVideoSdpDirection(obj.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE);
                                                    } else {
                                                        if (videoDirection === CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE) {
                                                            obj.sdp = sdpParser.updateVideoSdpDirection(obj.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE);
                                                        }
                                                        else {
                                                            obj.sdp = sdpParser.updateVideoSdpDirection(obj.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_ONLY);
                                                        }
                                                    }
                                                } else {
                                                    if (sdpParser.isSdpVideoSendEnabled(call.sdp)) {
                                                        obj.sdp = sdpParser.updateVideoSdpDirection(obj.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY);
                                                    } else {
                                                        obj.sdp = sdpParser.updateVideoSdpDirection(obj.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE);
                                                    }
                                                }
                                                //change audio's direction to sendrecv for ssl attendees in a 3wc
                                                obj.sdp = sdpParser.changeDirection(obj.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE, CONSTANTS.STRING.AUDIO);
                                            } else if (local_hold_status && !hold) {
                                                logger.debug("processHold: Remote UNHOLD on local hold");

                                                if (audioDirection === CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE) {
                                                    obj.sdp = sdpParser.updateAudioSdpDirectionToInactive(obj.sdp);
                                                } else {
                                                    obj.sdp = sdpParser.updateAudioSdpDirection(obj.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_ONLY);
                                                }

                                                if (webRtcAdaptorUtils.callCanLocalSendVideo(call)) {
                                                    obj.sdp = sdpParser.updateVideoSdpDirection(obj.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_ONLY);
                                                } else {
                                                    obj.sdp = sdpParser.updateVideoSdpDirectionToInactive(obj.sdp);
                                                }
                                            }

                                            obj.sdp = sdpParser.performVP8RTCPParameterWorkaround(obj.sdp);
                                            obj.sdp = sdpParser.updateVersion(peerLocalSdp, obj.sdp);
                                            obj.sdp = sdpParser.checkIceParamsLengths(obj.sdp, updateSdp.sdp);
                                            obj.sdp = sdpParser.fixLocalTelephoneEventPayloadType(call, obj.sdp);

                                            if (newPeerCreated) {
                                                obj.sdp = sdpParser.copyCandidatesToTheNewLocalSdp(peerLocalSdp, obj.sdp);
                                                newPeerCreated = false;
                                            }
                                            call.answer = obj.sdp;       // ABE-1328

                                            peer.setLocalDescription(
                                                    obj,
                                                    function processHoldSetLocalDescriptionSuccessCallback() {
                                                        if (sdpParser.isMediaPortReady(obj.sdp)) {
                                                            utils.callFunctionIfExist(successCallback, obj.sdp);
                                                            call.successCallback = null;
                                                            call.answer = null;
                                                        }
                                                    },
                                                    function processHoldSetLocalDescriptionFailureCallback(e) {
                                                        logger.debug("processHold: setLocalDescription failed!! " + e);
                                                        utils.callFunctionIfExist(failureCallback, "Session cannot be created");
                                                        call.answer = null;       // ABE-1328
                                                    });
                                        },
                                        function processHoldCreateAnswerFailureCallback(e){
                                            logger.debug("processHold: createAnswer failed!!: " + e);
                                            utils.callFunctionIfExist(failureCallback, "Session cannot be created");
                                        },
                                        {
                                            'mandatory': {
                                                'OfferToReceiveAudio': self.getMediaAudio(),
                                                'OfferToReceiveVideo': self.getMediaVideo()
                                            }
                                        });
                            },
                            function processHoldSetSecondRemoteDescriptionFailureCallback(e) {
                                logger.debug("processHold: second setRemoteDescription failed!! " + e);
                                utils.callFunctionIfExist(failureCallback, "Session cannot be created");
                            });
                },
                function processHoldSetFirstRemoteDescriptionFailureCallback(e) {
                    logger.debug("processHold: first setRemoteDescription failed!! " + e);
                    utils.callFunctionIfExist(failureCallback, "Session cannot be created");
                });
    };

    // Native implementation lies on webRtcAdaptor.js
    // processNativeUpdate
    self.processUpdate = function(call, successCallback, failureCallback, local_hold_status) {
        logger.debug("processUpdate: state= " + call.peer.signalingState);
        var peer = call.peer, remoteAudioState, remoteVideoState, remoteVideoDirection, callSdpWithNoSsrc,
                remoteDescObj, localDescObj, peerRemoteSdp, peerLocalSdp, newPeerCreated;

        call.stableRemoteSdp = peer.remoteDescription.sdp;
        call.stableLocalSdp = peer.localDescription.sdp;

        call.sdp = sdpParser.addSdpMissingCryptoLine(call.sdp); // Meetme workaround
        call.sdp = sdpParser.removeSdpPli(call.sdp);
        call.sdp = sdpParser.removeG722Codec(call.sdp);
        call.sdp = sdpParser.performG722ParameterWorkaround(call.sdp);
        call.sdp = sdpParser.performVP8RTCPParameterWorkaround(call.sdp);
        call.sdp = sdpParser.fixRemoteTelephoneEventPayloadType(call, call.sdp);
        call.sdp = sdpParser.checkAndRestoreICEParams(call.sdp, call.peer.localDescription.sdp);

        remoteVideoDirection = sdpParser.getVideoSdpDirection(call.sdp);

        self.setMediaVideo(sdpParser.isSdpHasVideo(call.sdp));
        if (remoteVideoDirection === CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE &&
                call.currentState === "COMPLETED")
        {
            switch(call.remoteVideoState){
                case CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE:
                    call.sdp = sdpParser.updateVideoSdpDirection(call.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE);
                    break;
                case CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY:
                    call.sdp = sdpParser.updateVideoSdpDirection(call.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE);
                    break;
                case CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE:
                    call.sdp = sdpParser.updateVideoSdpDirection(call.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY);
                    break;
            }
        }

        if (local_hold_status) {
            call.sdp = sdpParser.updateAudioSdpDirectionToInactive(call.sdp);
            call.sdp = sdpParser.updateVideoSdpDirectionToInactive(call.sdp);
        }

        call.sdp = sdpParser.changeDirection(call.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_ONLY, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE, CONSTANTS.STRING.VIDEO);
        webRtcAdaptorUtils.callSetReceiveVideo(call);

        if (peer.signalingState === CONSTANTS.WEBRTC.RTC_SIGNALING_STATE.HAVE_LOCAL_OFFER) {
            //if we are here we have been to createUpdate before this

            call.sdp = sdpParser.checkSupportedVideoCodecs(call.sdp, call.peer.localDescription.sdp);
            call.sdp = sdpParser.setMediaPassive(call.sdp, self.isDtlsEnabled());
            remoteDescObj = self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.ANSWER, call.sdp);

            peer.setRemoteDescription(
                    remoteDescObj,
                    function processUpdateSetRemoteDescriptionSuccessCallback() {
                        call.remoteVideoState = sdpParser.getVideoSdpDirection(call.sdp);
                        self.addCandidates(call);
                        utils.callFunctionIfExist(successCallback, call.sdp);
                        call.successCallback = null;
                    },
                    function processUpdateSetRemoteDescriptionFailureCallback(e) {
                        logger.debug("processUpdate: setRemoteDescription failed!!" + e);
                        utils.callFunctionIfExist(failureCallback, "processUpdate: setRemoteDescription failed!!");
                    });
        } else {
            call.sdp = sdpParser.checkSupportedVideoCodecs(call.sdp, null);
            //this part is a work-around for webrtc bug
            //set remote description with inactive media lines first.
            //then set remote description with original media lines.

            //keep original values of remote audio and video states
            remoteAudioState = sdpParser.getAudioSdpDirection(call.sdp);
            remoteVideoState = sdpParser.getVideoSdpDirection(call.sdp);

            //set media lines with inactive state for workaround
            call.sdp = sdpParser.updateAudioSdpDirectionToInactive(call.sdp);
            call.sdp = sdpParser.updateVideoSdpDirectionToInactive(call.sdp);

            //This is highly required for meetme on DTLS
            call.sdp = sdpParser.setMediaActPass(call.sdp, self.isDtlsEnabled());

            // delete all ssrc lines from the sdp before setting first remote description
            // set second remote description with all ssrc lines included
            if (remoteVideoState === CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE ||
                    remoteVideoState === CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY)
            {
                call.sdp = sdpParser.deleteInactiveVideoSsrc(call.sdp);
            }

            peerRemoteSdp = self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.OFFER, call.prevRemoteSdp);
            peerLocalSdp = peer.localDescription.sdp;

            if (self.createNewPeerForCallIfIceChangedInRemoteSdp(call, call.sdp, peerRemoteSdp.sdp)) {
                peer = call.peer;
                newPeerCreated = true;
            }

            callSdpWithNoSsrc = sdpParser.deleteSsrcFromSdp(call.sdp);
            remoteDescObj = self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.OFFER, callSdpWithNoSsrc);

            peer.setRemoteDescription(
                    remoteDescObj,
                    function processUpdateWorkaroundSetRemoteDescriptionSuccessCallback() {
                        logger.debug("processUpdate: workaround setRemoteDescription success");

                        //restore original values
                        call.sdp = sdpParser.updateAudioSdpDirection(call.sdp, remoteAudioState);
                        call.sdp = sdpParser.updateVideoSdpDirection(call.sdp, remoteVideoState);

                        remoteDescObj = self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.OFFER, call.sdp);
                        peer.setRemoteDescription(
                                remoteDescObj,
                                function processUpdateSetRemoteDescriptionSuccessCallback() {
                                    logger.debug("processUpdate: setRemoteDescription success");
                                    call.remoteVideoState = sdpParser.getVideoSdpDirection(call.sdp);
                                    self.addCandidates(call);

                                    peer.createAnswer(
                                            function processUpdateCreateAnswerSuccessCallback(obj) {
                                                logger.debug("processUpdate: isSdpEnabled audio= " + sdpParser.isAudioSdpEnabled(obj.sdp));
                                                logger.debug("processUpdate: isSdpEnabled video= " + sdpParser.isVideoSdpEnabled(obj.sdp));

                                                if (remoteAudioState === CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE) {
                                                    obj.sdp = sdpParser.updateAudioSdpDirectionToInactive(obj.sdp);
                                                }

                                                if (call.remoteVideoState === CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE) {
                                                    obj.sdp = sdpParser.updateVideoSdpDirectionToInactive(obj.sdp);
                                                } else if (webRtcAdaptorUtils.callCanLocalSendVideo(call)) {
                                                    obj.sdp = sdpParser.updateVideoSdpDirection(obj.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE);
                                                } else {
                                                    obj.sdp = sdpParser.updateVideoSdpDirection(obj.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY);
                                                }
                                                obj.sdp = sdpParser.performVP8RTCPParameterWorkaround(obj.sdp);
                                                obj.sdp = sdpParser.updateVersion(peerLocalSdp, obj.sdp);
                                                obj.sdp = sdpParser.fixLocalTelephoneEventPayloadType(call, obj.sdp);

                                                self.fireOnStreamAddedEvent(call);

                                                obj.sdp = sdpParser.checkIceParamsLengths(obj.sdp, remoteDescObj.sdp);
                                                obj.sdp = sdpParser.setMediaPassive(obj.sdp, self.isDtlsEnabled());

                                                if (newPeerCreated) {
                                                    obj.sdp = sdpParser.copyCandidatesToTheNewLocalSdp(peerLocalSdp, obj.sdp);
                                                    newPeerCreated = false;
                                                }
                                                localDescObj = self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.ANSWER, obj.sdp);

                                                peer.setLocalDescription(
                                                        localDescObj,
                                                        function processUpdateSetLocalDescriptionSuccessCallback() {
                                                            if (sdpParser.isMediaPortReady(obj.sdp)) {
                                                                logger.debug("processUpdate: setlocalDescription success");
                                                                utils.callFunctionIfExist(successCallback, obj.sdp);
                                                                call.successCallback = null;
                                                            }
                                                        },
                                                        function processUpdateSetLocalDescriptionSuccessCallback(e) {
                                                            logger.debug("processUpdate: setlocalDescription failed!!" + e);
                                                            utils.callFunctionIfExist(failureCallback, "processUpdate: setlocalDescription failed!!");
                                                        });
                                            },
                                            function processUpdateCreateAnswerFailureCallback(e) {
                                                logger.debug("processUpdate: createAnswer failed!! " + e);
                                                utils.callFunctionIfExist(failureCallback, "Session cannot be created");
                                            },
                                            {
                                                'mandatory': {
                                                    'OfferToReceiveAudio': self.getMediaAudio(),
                                                    'OfferToReceiveVideo': self.getMediaVideo()
                                                }
                                            });
                                },
                                function processUpdateSetRemoteDescriptionSuccessCallback(e) {
                                    logger.debug("processUpdate: setRemoteDescription failed!!" + e);
                                    utils.callFunctionIfExist(failureCallback, "processUpdate: setRemoteDescription failed!!");
                                });
                    },
                    function processUpdateWorkaroundSetRemoteDescriptionSuccessCallback(e) {
                        logger.debug("processUpdate: workaround setRemoteDescription failed!!" + e);
                        utils.callFunctionIfExist(failureCallback, "processUpdate: workaround setRemoteDescription failed!!");
                    });
        }
    };

    // Native implementation lies on webRtcAdaptor.js
    // processNativeAnswer
    self.processAnswer = function(call, onSuccess, onFail) {
        logger.debug("processAnswer: state= " + call.peer.signalingState);
        var restoreSdpOnSuccess, audioWorkaroundOnSuccess, onSuccessAfterWorkarounds,
                remoteVideoDirection, localVideoDirection,
                peer = call.peer;

        onSuccessAfterWorkarounds = function() {
            call.remoteVideoState = sdpParser.getVideoSdpDirection(call.sdp);
            call.videoOfferSent = sdpParser.isSdpHasVideo(call.sdp);
            self.addCandidates(call);
            utils.callFunctionIfExist(onSuccess);
        };

        call.sdp = sdpParser.checkSupportedVideoCodecs(call.sdp, peer.localDescription.sdp);
        call.sdp = sdpParser.performVideoPortZeroWorkaround(call.sdp);
        call.sdp = sdpParser.removeSdpPli(call.sdp);
        call.sdp = sdpParser.removeG722Codec(call.sdp);
        call.sdp = sdpParser.performG722ParameterWorkaround(call.sdp);
        call.sdp = sdpParser.performVP8RTCPParameterWorkaround(call.sdp);
        call.sdp = sdpParser.performVP8BandwidthWorkaround(call.sdp);
        call.sdp = sdpParser.fixRemoteTelephoneEventPayloadType(call, call.sdp);

        webRtcAdaptorUtils.callSetReceiveVideo(call);

        remoteVideoDirection = sdpParser.getVideoSdpDirection(call.sdp);
        localVideoDirection = sdpParser.getVideoSdpDirection(call.peer.localDescription.sdp);

        // this is needed for buggy webrtc api. when term answers with video to audio only call
        // this scenario does not work without converting to sendrecv
        logger.debug("processAnswer: ice-lite: do remote video escalation");
        call.sdp = sdpParser.changeDirection(call.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_ONLY, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE);

        if (localVideoDirection === CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY &&
                (remoteVideoDirection === CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE || remoteVideoDirection === CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY)) {

            // delete ssrc only from video, keep audio ssrc to hear audio
            call.sdp = sdpParser.deleteInactiveVideoSsrc(call.sdp);

            // Audio <--> Audio : apply workaround step 1

            self.performOrigAudioWorkaround(call, onSuccessAfterWorkarounds, onFail);

        } else if (localVideoDirection === CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE &&
                (remoteVideoDirection === CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY || remoteVideoDirection === CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE)) {

            // delete ssrc only from video, keep audio ssrc to hear audio
            call.sdp = sdpParser.deleteInactiveVideoSsrc(call.sdp);

            // Audio-Video <--> Audio : apply workaround step 1 & 2

            audioWorkaroundOnSuccess = function() {
                self.restoreActualSdp(call, onSuccessAfterWorkarounds, onFail, localVideoDirection, remoteVideoDirection);
            };

            //self.performOrigAudioWorkaround(call, audioWorkaroundOnSuccess, onFail);
            self.performOrigAudioWorkaround(call, onSuccessAfterWorkarounds, onFail);

        } else if (localVideoDirection === CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY &&
                (remoteVideoDirection === CONSTANTS.WEBRTC.MEDIA_STATE.SEND_ONLY || remoteVideoDirection === CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE)) {

            // Audio  <--> Audio-Video

            restoreSdpOnSuccess = function() {
                self.performVideoStartWorkaround(call, onSuccessAfterWorkarounds, onFail);
            };

            audioWorkaroundOnSuccess = function() {
                self.restoreActualSdp(call, restoreSdpOnSuccess, onFail, localVideoDirection, remoteVideoDirection);
            };

            //self.performOrigAudioWorkaround(call, audioWorkaroundOnSuccess, onFail);
            self.performOrigAudioWorkaround(call, restoreSdpOnSuccess, onFail);

        } else {

            // Audio-Video <--> Audio-Video
            // there is remote video, no need for orig side workaround

            call.sdp = sdpParser.setMediaPassive(call.sdp, self.isDtlsEnabled());

            peer.setRemoteDescription(
                    self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.ANSWER, call.sdp),
                    function processAnswerSetRemoteDescriptionSuccessCallback() {
                        logger.debug("processAnswer: setRemoteDescription success");
                        onSuccessAfterWorkarounds();
                    },
                    function processAnswerSetRemoteDescriptionFailureCallback(e) {
                        logger.debug("processAnswer: setRemoteDescription failed: " + e);
                        utils.callFunctionIfExist(onFail);
                    });
        }

    };

    // Native implementation lies on webRtcAdaptor.js
    // processNativePreAnswer
    self.processPreAnswer = function(call) {
        logger.debug("processPreAnswer: state= " + call.peer.signalingState);
        var peer = call.peer, remoteDesc;

        call.sdp = sdpParser.checkSupportedVideoCodecs(call.sdp, call.peer.localDescription.sdp);
        call.sdp = sdpParser.removeG722Codec(call.sdp);
        call.sdp = sdpParser.performG722ParameterWorkaround(call.sdp);
        call.sdp = sdpParser.performVP8RTCPParameterWorkaround(call.sdp);
        call.sdp = sdpParser.fixRemoteTelephoneEventPayloadType(call, call.sdp);

        webRtcAdaptorUtils.callSetReceiveVideo(call);
        remoteDesc = self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.ANSWER, call.sdp);
        self.addCandidates(call);
        peer.setRemoteDescription(
                remoteDesc,
                function processPreAnswerSetRemoteDescriptionSuccessCallback(){
                    call.remoteVideoState = sdpParser.getVideoSdpDirection(call.sdp);
                    logger.debug("processPreAnswer: setRemoteDescription success");
                },
                function processPreAnswerSetRemoteDescriptionFailureCallback(e) {
                    logger.debug("processPreAnswer: setRemoteDescription failed: " + e );
                });
    };

    // Native implementation lies on webRtcAdaptor.js
    // processNativeRespond
    self.processRespond = function(call, onSuccess, onFail, isJoin) {
        var remoteVideoDirection, callSdpWithNoSsrc, remoteDescObj,
                peer = call.peer;
        logger.debug("processRespond: state= " + call.peer.signalingState);

        call.sdp = sdpParser.checkSupportedVideoCodecs(call.sdp, peer.localDescription.sdp);
        call.sdp = sdpParser.removeSdpPli(call.sdp);
        call.sdp = sdpParser.removeG722Codec(call.sdp);
        call.sdp = sdpParser.performG722ParameterWorkaround(call.sdp);
        call.sdp = sdpParser.performVP8RTCPParameterWorkaround(call.sdp);
        call.sdp = sdpParser.performVP8BandwidthWorkaround(call.sdp);
        call.sdp = sdpParser.fixRemoteTelephoneEventPayloadType(call, call.sdp);

        remoteVideoDirection = sdpParser.getVideoSdpDirection(call.sdp);
        webRtcAdaptorUtils.callSetReceiveVideo(call);

        if ((remoteVideoDirection === CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE) && (call.currentState === "COMPLETED"))
        {
            switch(call.remoteVideoState){
                case CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE:
                    call.sdp = sdpParser.updateVideoSdpDirection(call.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY);
                    break;
                case CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY:
                    call.sdp = sdpParser.updateVideoSdpDirection(call.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY);
                    break;
            }
        }
        call.remoteVideoState = sdpParser.getVideoSdpDirection(call.sdp);
        call.sdp = sdpParser.changeDirection(call.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_ONLY, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE, CONSTANTS.STRING.VIDEO);

        if (isJoin) {
            call.sdp = sdpParser.changeDirection(call.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE, CONSTANTS.STRING.AUDIO);
            self.muteOnHold(call, false);
        }

        if (call.peer.signalingState === CONSTANTS.WEBRTC.RTC_SIGNALING_STATE.STABLE) {
            //if we are in stable state we should not change remotedescription
            utils.callFunctionIfExist(onSuccess);
            return;
        }

        call.sdp = sdpParser.setMediaPassive(call.sdp, self.isDtlsEnabled());
        // delete all ssrc lines from the sdp before setting first remote description
        // set second remote description with all ssrc lines included

        if (sdpParser.getVideoSdpDirection(call.sdp) === CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE ||
                sdpParser.getVideoSdpDirection(call.sdp) === CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY)
        {
            call.sdp = sdpParser.deleteInactiveVideoSsrc(call.sdp);
        }
        callSdpWithNoSsrc = sdpParser.deleteSsrcFromSdp(call.sdp);
        remoteDescObj = self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.ANSWER, callSdpWithNoSsrc);

        peer.setRemoteDescription(
                remoteDescObj,
                function processRespondSetRemoteDescriptionSuccessCallback() {
                    logger.debug("processRespond: setRemoteDescription success");
                    var onSuccessAfterWorkarounds = function() {
                        call.remoteVideoState = sdpParser.getVideoSdpDirection(call.sdp);
                        call.videoOfferSent = true;
                        self.addCandidates(call);
                        utils.callFunctionIfExist(onSuccess);
                    };
                    self.performVideoStartWorkaround(call, onSuccessAfterWorkarounds, onFail);
                },
                function processRespondSetRemoteDescriptionSuccessCallback(e) {
                    logger.debug("processRespond: setRemoteDescription failed: " + e);
                    utils.callFunctionIfExist(onFail);
                });
    };

    /*
     * Native implementation lies on webRtcAdaptor.js
     * processNativeHoldRespond
     */
    self.processHoldRespond = function(call, onSuccess, onFailure, isJoin) {
        var remoteAudioDirection,
            remoteVideoDirection,
            localVideoDirection,
            onSuccessAfterWorkaround,
            localHoldFlag = false,
            remoteHoldFlag = false,
            obj;

        onSuccessAfterWorkaround = function() {
            //call.remoteVideoState = getSdpDirection(call.sdp, video);
            self.addCandidates(call);
            utils.callFunctionIfExist(onSuccess);
        };

        logger.debug("processHoldRespond: state= " + call.peer.signalingState + " call.currentState= " + call.currentState);

        call.sdp = sdpParser.checkSupportedVideoCodecs(call.sdp, call.peer.localDescription.sdp);
        call.sdp = sdpParser.removeSdpPli(call.sdp);
        call.sdp = sdpParser.removeG722Codec(call.sdp);
        call.sdp = sdpParser.performG722ParameterWorkaround(call.sdp);
        call.sdp = sdpParser.performVP8RTCPParameterWorkaround(call.sdp);
        call.sdp = sdpParser.performVP8BandwidthWorkaround(call.sdp);
        call.sdp = sdpParser.fixRemoteTelephoneEventPayloadType(call, call.sdp);

        sdpParser.init(call.sdp);
        remoteHoldFlag = sdpParser.isRemoteHold();

        localHoldFlag = (call.currentState === "LOCAL_HOLD");

        remoteAudioDirection = sdpParser.getAudioSdpDirection(call.sdp);
        remoteVideoDirection = sdpParser.getVideoSdpDirection(call.sdp);

        call.remoteVideoState = remoteVideoDirection;

        localVideoDirection = sdpParser.getVideoSdpDirection(call.peer.localDescription.sdp);

        logger.debug("processHoldRespond: localHold= " + localHoldFlag + " remoteHold= " + remoteHoldFlag);

        /* Required for MOH - start */
        if (remoteHoldFlag === false) {
            if ((remoteAudioDirection === CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE) && (call.currentState === "REMOTE_HOLD")) {
                logger.debug("set current web state to COMPLETED");
                call.previousState = call.currentState;
                call.currentState = "COMPLETED";
            }
        } else {
            if (call.currentState === "COMPLETED") {
                logger.debug("set current web state to REMOTE_HOLD");
                call.previousState = call.currentState;
                call.currentState = "REMOTE_HOLD";
            }
        }

        if (localHoldFlag || remoteHoldFlag) {
            logger.debug("processHoldRespond: " + call.currentState + " : video -> inactive");
            call.sdp = sdpParser.updateVideoSdpDirection(call.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE);
        }

        if ((remoteVideoDirection === CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE) && (call.currentState === "COMPLETED")) {
            logger.debug("processHoldRespond: video inactive -> recvonly");
            call.sdp = sdpParser.updateVideoSdpDirection(call.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY);
        }
        /* Required for MOH - end */

        if (isJoin) {
            self.muteOnHold(call, false);
        }

        // this is required just before setRemoteDescription
        webRtcAdaptorUtils.callSetReceiveVideo(call);

        if (call.peer.signalingState === CONSTANTS.WEBRTC.RTC_SIGNALING_STATE.STABLE) {
            //if we are in stable state we should not change remotedescription
            utils.callFunctionIfExist(onSuccess);
            return;
        }

        call.sdp = sdpParser.setMediaPassive(call.sdp, self.isDtlsEnabled());

        // this is required for displaying remote video when direction is send only
        call.sdp = sdpParser.changeDirection(call.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_ONLY, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE);
        if (sdpParser.getVideoSdpDirection(call.sdp) === CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE ||
                sdpParser.getVideoSdpDirection(call.sdp) === CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY)
        {
            call.sdp = sdpParser.deleteInactiveVideoSsrc(call.sdp);
        }

        obj = self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.ANSWER, call.sdp);

        call.peer.setRemoteDescription(obj,
                function processHoldRespondSetRemoteDescriptionSuccessCallback() {
                    logger.debug("processHoldRespond: setRemoteDescription typeAns success");
                    if (remoteAudioDirection === CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE ||
                        remoteAudioDirection === CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY) {
                        onSuccessAfterWorkaround();
                    } else {
                        self.performVideoStartWorkaround(call, onSuccessAfterWorkaround, onFailure);
                    }
                },
                function processHoldRespondSetRemoteDescriptionFailureCallback(e) {
                    logger.debug("processHoldRespond: setRemoteDescription typeAns failed: " + e);
                    utils.callFunctionIfExist(onFailure);
                });
    };

    // Native implementation lies on webRtcAdaptor.js
    self.processRemoteOfferOnLocalHold = function(call, successCallback, failureCallback) {
        logger.info("processRemoteOfferOnLocalHold");
        if (call.peer) {
            utils.callFunctionIfExist(successCallback, call.peer.localDescription.sdp);
        }
        else {
            utils.callFunctionIfExist(failureCallback, "we dont have a peer object somehow");
        }
    };

    /*
     * Native implementation lies on webRtcAdaptor.js
     * process the end call that was received
     *
     * @ignore
     * @name rtc.processEnd.stop
     */
    self.processEnd = function(call) {
        if (call.peer) {
            logger.info("close peer connection " + call.id);
            // void close()
            if (call.peer) {
                call.peer.close();
            }
            if(call.localStream) {
                call.localStream.stop();
                call.localStream = null;
            }

            if (self.getDefaultVideoContainer()) {
                if(self.getDefaultVideoContainer().firstElementChild) {
                    self.disposeStreamRenderer(self.getDefaultVideoContainer().firstElementChild);
                }
            } else if (self.getRemoteVideoContainer()) {
                self.disposeStreamRenderer(self.getRemoteVideoContainer());
            }

            self.setPeerCount(self.getPeerCount() - 1);
            if(self.getPeerCount() <=0) {
                if(self.getLocalStream() && self.getLocalStream().stop) {
                    self.getLocalStream().stop();
                    if (self.getDefaultVideoContainer()) {
                        self.disposeStreamRenderer(self.getDefaultVideoContainer().lastElementChild);
                    } else if(self.getLocalVideoContainer()) {
                        self.disposeStreamRenderer(self.getLocalVideoContainer());
                    }
                }
                self.setLocalStream(null);
            }
        }

    };

    self.createUpdateWithSetLocalDescription = function(call, successCallback, failureCallback, isVideoStart, localSdp) {
        var peer = call.peer, localDesc;
        logger.debug("set local description to start the video");

        if (!call.isVideoSourceAllowed) {
            self.replaceLocalStream(call);
        }
        if (self.getLocalVideoTrack(call.peer)) {
            self.getLocalVideoTrack(call.peer).enabled = isVideoStart;
        }
        if (isVideoStart) {
            localSdp = sdpParser.updateSdpDirection(localSdp, CONSTANTS.STRING.VIDEO, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE);
        } else {
            localSdp = sdpParser.deescalateSdpDirection(localSdp, CONSTANTS.STRING.VIDEO);
        }

        localDesc = self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.OFFER, localSdp);

        peer.setLocalDescription(localDesc,
            function createUpdateSetLocalDescriptionSuccessCallback() {
                //since the candidates are same we can call the successCallback
                logger.debug("createUpdate: setLocalDescription success ");
                utils.callFunctionIfExist(successCallback, localDesc.sdp);
            },
            function createUpdateSetLocalDescriptionFailureCallback(e) {
                logger.error("createUpdate: setLocalDescription failed : " + e);
                utils.callFunctionIfExist(failureCallback);
            });
    };

    self.createUpdateWithCreateOffer = function(call, successCallback, failureCallback, isVideoStart, localSdp, isIceLite) {
        var peer = call.peer, localDesc;
        logger.debug("create new offer to start the video: isIceLite = " + isIceLite);

        self.replaceLocalStream(call);
        self.setMediaVideo(sdpParser.isSdpHasVideo(localSdp));
        peer.createOffer(
            function createUpdateCreateOfferSuccessCallback(obj) {
                isVideoStart = isVideoStart && self.getVideoSourceAvailable();
                if (isVideoStart) {
                    obj.sdp = sdpParser.updateVideoSdpDirection(obj.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE);
                } else {
                    obj.sdp = sdpParser.updateVideoSdpDirection(obj.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY);
                }

                obj.sdp = sdpParser.performVP8RTCPParameterWorkaround(obj.sdp);
                obj.sdp = sdpParser.setMediaActPass(obj.sdp, self.isDtlsEnabled());
                obj.sdp = sdpParser.fixLocalTelephoneEventPayloadType(call, obj.sdp);
                obj.sdp = sdpParser.replaceOpusCodec(obj.sdp);
                obj.sdp = sdpParser.deleteCryptoZeroFromSdp(obj.sdp);
                obj.sdp = sdpParser.updateAudioCodec(obj.sdp);
                obj.sdp = sdpParser.removeG722Codec(obj.sdp);
                obj.sdp = sdpParser.deleteCryptoFromSdp(obj.sdp, self.isDtlsEnabled());

                localDesc = self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.OFFER, obj.sdp);

                peer.setLocalDescription(localDesc,
                    function createUpdateCreateOfferSetLocalDescriptionSuccessCallback() {
                        //since the candidates have changed we will call the successCallback at onNativeIceCandidate
                        //utils.callFunctionIfExist(successCallback);
                        logger.debug("createUpdate: createOffer setLocalDescription success ");
                        webRtcAdaptorUtils.setLocalStreamVideoSendStatus(call, isVideoStart);
                    },
                    function crateUpdateCreateOfferSetLocalDescriptionFailureCallback(e) {
                        logger.debug("createUpdate: createOffer setLocalDescription failed: " + e);
                        utils.callFunctionIfExist(failureCallback);
                    });
            },
            function createUpdateCrateOfferFailureCallback(e) {
                logger.debug("createUpdate: createOffer failed!!: " + e);
                failureCallback();
            },
            {
                'mandatory': {
                    'OfferToReceiveAudio': self.getMediaAudio(),
                    'OfferToReceiveVideo': self.getMediaVideo(),
                    'IceRestart': !isIceLite
                }
            }
        );

    };

    // Native implementation lies on webRtcAdaptor.js
    self.onSessionConnecting = function(call, message) {
        logger.debug("onSessionConnecting");
    };

    // Native implementation lies on webRtcAdaptor.js
    self.onSessionOpened = function(call, message) {
        logger.debug("onSessionOpened");
    };

    // Native implementation lies on webRtcAdaptor.js
    self.onSignalingStateChange = function(call, event) {
        //TODO may need to move the state changes for webrtc here
        logger.debug("Signalling state changed: state= " + event.srcElement.signalingState);
    };

    // Native implementation lies on webRtcAdaptor.js
    self.useDefaultRenderer = function(streamUrl, local) {
        var videoContainer;

        if (self.getDefaultVideoContainer() && self.getDefaultVideoContainer().children.length === 0) {
            //Create divs for the remote and local
            self.getDefaultVideoContainer().innerHTML = "<div style='height:100%;width:100%'></div><div style='position:absolute;bottom:10px;right:10px;height:30%; width:30%;'></div>";
        }

        if (local) {
            if(self.getLocalVideoContainer()){
                videoContainer = self.getLocalVideoContainer();
            } else {
                videoContainer = self.getDefaultVideoContainer().lastElementChild;
            }
        } else {
            if(self.getRemoteVideoContainer()){
                videoContainer = self.getRemoteVideoContainer();
            } else {
                videoContainer = self.getDefaultVideoContainer().firstElementChild;
            }
        }
        self.createStreamRenderer(streamUrl, videoContainer, {muted: local});
    };

    // Native implementation lies on webRtcAdaptor.js
    self.createStreamRenderer = function(streamUrl, container, options){
        var renderer;

        if(!streamUrl || !container){
            return;
        }

        container.innerHTML = "";
        renderer = document.createElement('video');
        renderer.src = streamUrl;

        renderer.style.width = "100%";
        renderer.style.height = "100%";

        renderer.autoplay = "true";

        if (options) {
            if (options.muted) {
                renderer.muted = "true";
            }
        }

        container.appendChild(renderer);
        return renderer;
    };

    // Native implementation lies on webRtcAdaptor.js
    self.onRemoteStreamAdded = function(call, event) {
        var streamUrl;
        logger.debug("onRemoteStreamAdded");
        if (event.stream) {
            streamUrl = self.getRtcLibrary().getURLFromStream(event.stream);
            //TODO Is this neccessary?
            if (event.stream.getVideoTracks()) {
                logger.info("Accessed Video Track");
            }
            if (streamUrl) {
                logger.debug("onRemoteStreamAdded: " + streamUrl);
                if (self.getDefaultVideoContainer()) {
                    self.useDefaultRenderer(streamUrl, false);
                } else if (self.getRemoteVideoContainer()) {
                    self.createStreamRenderer(streamUrl, self.getRemoteVideoContainer());
                } else {
                    self.fireOnStreamAddedEvent(call, streamUrl);
                }
            }
        }
    };

    // Native implementation lies on webRtcAdaptor.js
    self.fireOnStreamAddedEvent = function(call, streamUrl) {
        if (call && call.call && call.call.onStreamAdded) {
            webRtcAdaptorUtils.callSetReceiveVideo(call);
            utils.callFunctionIfExist(call.call.onStreamAdded, streamUrl);
        }
    };

    // Native implementation lies on webRtcAdaptor.js
    self.onRemoteStreamRemoved = function(call, event) {
        logger.debug("onRemoteStreamRemoved");

        //Ersan - Multiple Call Plugin Issue Tries
        //
        //event.stream.stop();
        //if (defaultVideoContainer) {
        //    if(defaultVideoContainer.firstElementChild) {
        //        disposeStreamRenderer(defaultVideoContainer.firstElementChild);
        //    }
        //} else if (remoteVideoContainer) {
        //    disposeStreamRenderer(remoteVideoContainer);
        //}
    };

    // Native implementation lies on webRtcAdaptor.js
    self.clearIceCandidateCollectionTimer = function(call) {
        //This method wasn't implemented in webrtc.js
        clearTimeout(call.iceCandidateCollectionTimer);
        call.iceCandidateCollectionTimer = null;
    };

    // Native implementation lies on webRtcAdaptor.js
    self.onIceCandidate = function(call, event) {
        var sdp;
        if(event.candidate === null) {
            self.clearIceCandidateCollectionTimer(call);
            if(call.successCallback) {
                logger.debug("Null candidate received, invoking successCallback.");
                sdp = call.peer.localDescription.sdp;
                call.successCallback(sdp);
                call.successCallback = null;
            }
        } else {
            call.iceCandidateReceived = true;
            logger.debug("ICE candidate received: sdpMLineIndex = " + event.candidate.sdpMLineIndex
                    + ", candidate = " + event.candidate.candidate + " for call : " + call.id);
        }
    };

    // Native implementation lies on webRtcAdaptor.js
    self.onIceComplete = function(call) {
        var  sdp;
        logger.debug("All ICE candidates received for call : " + call.id);
        self.clearIceCandidateCollectionTimer(call);

        if(call.successCallback) {
            if(call.offer) {
                sdp = call.offer.sdp;
                sdp = sdp.replace("s=","s=genband");
                call.offer = null;      // ABE-1328
            } else if(call.answer) {
                sdp = call.answer.sdp;
                call.answer = null;     // ABE-1328
            }

            sdp = sdpParser.updateH264Level(sdp);

            logger.debug("onIceComplete sdp : " + sdp);

            call.successCallback(sdp);
            call.successCallback = null;
        }
    };

    // Native implementation lies on webRtcAdaptor.js
    self.iceCandidateCollectionTimeoutHandler = function(call) {
        var sdp = call.peer.localDescription.sdp;
        self.clearIceCandidateCollectionTimer(call);

        // set timeout if there is no ice candidate available or
        // when audio, video port assignment isn't complete
        if ((sdpParser.isSdpHasAudio(sdp) && sdpParser.isSdpHasAudioWithZeroPort(sdp)) ||
                (sdpParser.isSdpHasVideo(sdp) && sdpParser.isSdpHasVideoWithZeroPort(sdp))) {
            logger.debug("Re-setting ice candidate collection timeout: " + fcsConfig.iceCandidateCollectionTimeoutInterval);
            call.iceCandidateCollectionTimer = setTimeout(function() {
                self.iceCandidateCollectionTimeoutHandler(call);
            }, fcsConfig.iceCandidateCollectionTimeoutInterval);
            return;
        }

        if (call.successCallback) {
            logger.debug("Ice candidate collection interrupted after given timeout, invoking successCallback.");
            call.successCallback(sdp);
            call.successCallback = null;
        }
    };

    // Native implementation lies on webRtcAdaptor.js
    self.setupIceCandidateCollectionTimer = function(call) {
        if (fcsConfig.iceCandidateCollectionTimeoutInterval) {
            if (!call.iceCandidateCollectionTimer) {
                logger.debug("Setting ice candidate collection timeout: " + fcsConfig.iceCandidateCollectionTimeoutInterval);
                call.iceCandidateCollectionTimer = setTimeout(function() {
                    self.iceCandidateCollectionTimeoutHandler(call);
                }, fcsConfig.iceCandidateCollectionTimeoutInterval);
            } else {
                logger.trace("Ice candidate collection timer exists.");
            }
        }
    };

    self.oniceconnectionstatechange = function(call, event) {
        logger.debug("ICE connection state change : " + event.currentTarget.iceConnectionState);
        if (call.peer.iceConnectionState === "failed") {
            utils.callFunctionIfExist(call.onIceStateFailure, call);
        }
    };

    // Native implementation lies on webRtcAdaptor.js
    self.createPeer = function(call, onSuccess, onFailure) {
        try {
            var pc, constraints, i, servers = [], iceServerUrl = self.getIceServerUrl(), stunturn;
            if (iceServerUrl instanceof Array) {
                for(i = 0; i<iceServerUrl.length; i++) {
                    servers[i] = iceServerUrl[i];
                }
            } else if (iceServerUrl === null ||  iceServerUrl === ""){
                servers = [];
            } else {
                servers[0] = iceServerUrl;
            }
            stunturn = {iceServers:servers};

            constraints = {"optional": [{"DtlsSrtpKeyAgreement": self.isDtlsEnabled()}]};
            pc = self.getRtcLibrary().createRTCPeerConnection(stunturn, constraints);

            self.setPeerCount(self.getPeerCount() + 1);
            call.peer = pc;

            pc.onconnecting = function(event){
                self.onSessionConnecting(call, event);
            };
            pc.onopen = function(event){
                self.onSessionOpened(call, event);
            };
            pc.onsignalingstatechange = function(event){
                self.onSignalingStateChange(call, event);
            };
            pc.onaddstream = function(event){
                self.onRemoteStreamAdded(call, event);
            };
            pc.onremovestream = function(event){
                self.onRemoteStreamRemoved(call, event);
            };
            pc.onicecandidate = function(event){
                self.setupIceCandidateCollectionTimer(call);
                self.onIceCandidate(call, event);
            };
            pc.onicecomplete = function(){
                self.onIceComplete(call);
            };
            pc.oniceconnectionstatechange = function (event) {
                self.oniceconnectionstatechange(call, event);
            };
            logger.info("create PeerConnection successfully.");
            onSuccess(call);
        } catch(err) {
            logger.error("Failed to create PeerConnection, exception: " + err.message);
            onFailure();
        }
    };

    self.createNewPeerForCall = function(call) {
        var isNewPeerCreated = false, peerCount = self.getPeerCount();
        if (call.peer) {
            call.peer.close();
            self.setPeerCount(peerCount - 1);
        }

        logger.trace("Creating new peer for call: " + call.id);
        self.createPeer(call, function createPeerSuccessCallback() {
            logger.trace("New peer has created for call: " + call.id);
            call.peer.addStream(self.getLocalStream());
            isNewPeerCreated = true;
        }, function createPeerFailureCallback() {
            logger.error("New peer creation has failed!: " + call.id);
        });
        return isNewPeerCreated;
    };

    // Native implementation lies on webRtcAdaptor.js
    self.createNewPeerForCallIfIceChangedInRemoteSdp = function(call, newSdp, oldSdp) {
        var hasNewSdpContainsIceLite = sdpParser.isIceLite(newSdp),
                hasOldSdpContainsIceLite = sdpParser.isIceLite(oldSdp),
                isNewPeerCreated = false;

        // In Peer-Peer call, ice-iceLite change indicates
        // a new peer connection with different ip.
        // As for now, webrtc cannot handle ip change
        // without creating a peer.
        // For ex: Peer-Peer call and MoH.
        //
        // In Non Peer-Peer call, ice-iceLite change does
        // not occur so existing peer object will be used.

        if (hasNewSdpContainsIceLite !== hasOldSdpContainsIceLite) {
            logger.trace("Ice - Ice-Lite change detected in call: " + call.id);
            return self.createNewPeerForCall(call);
        }

        return isNewPeerCreated;
    };

    /*
     *TODO It is weird that this returns empty array in native
     * Native implementation lies on webRtcAdaptor.js
     */
    self.getRemoteVideoResolutions = function() {
        return [];
    };

    /*
     *TODO It is weird that this returns empty array in native
     * Native implementation lies on webRtcAdaptor.js
     */
    self.getLocalVideoResolutions = function() {
        return [];
    };

    // Native implementation lies on webRtcAdaptor.js
    self.refreshVideoRenderer = function() {
        return;
    };

    // Native implementation lies on webRtcAdaptor.js
    self.sendIntraFrame = function() {
        return;
    };

    // Native implementation lies on webRtcAdaptor.js
    self.sendBlackFrame = function() {
        return;
    };

    // Native implementation lies on webRtcAdaptor.js
    // TODO is this function really necessary?
    self.fireOnLocalStreamAddedEvent = function(call) {
        if (call && call.call && call.call.onLocalStreamAdded) {
            utils.callFunctionIfExist(call.call.onLocalStreamAdded);
        }
    };

    //This function is called internally when we make a new call or hold/unhold scenario
    // Native implementation lies on webRtcAdaptor.js
    self.addLocalStream = function(internalCall) {
        var streamUrl, fireEvent = false;
        logger.debug("addLocalStream");

        if (internalCall.localStream) {
            if (webRtcAdaptorUtils.callCanLocalSendVideo(internalCall)) {
                streamUrl = self.getRtcLibrary().getURLFromStream(internalCall.localStream);

                if (streamUrl) {
                    logger.debug("addLocalStream: " + streamUrl);
                    if (self.getDefaultVideoContainer()) {
                        self.useDefaultRenderer(streamUrl, true);
                    } else if (self.getLocalVideoContainer()) {
                        self.createStreamRenderer(streamUrl, self.getLocalVideoContainer(), {muted: true});
                    } else {
                        internalCall.call.localStreamURL = streamUrl;
                    }
                    fireEvent = true;
                }
            } else {
                if (self.getDefaultVideoContainer()) {
                    if(self.getDefaultVideoContainer().lastElementChild) {
                        self.disposeStreamRenderer(self.getDefaultVideoContainer().lastElementChild);
                        fireEvent = true;
                    }
                } else if (self.getLocalVideoContainer()) {
                    self.disposeStreamRenderer(self.getLocalVideoContainer());
                    fireEvent = true;
                }
            }

            if (fireEvent) {
                self.fireOnLocalStreamAddedEvent(internalCall);
            }
        }
    };

    // Native implementation lies on webRtcAdaptor.js
    self.replaceLocalStream = function(internalCall) {
        logger.debug("replaceLocalStream");
        if (internalCall.peer.getLocalStreams().length > 0) {
            internalCall.peer.removeStream(internalCall.peer.getLocalStreams()[0]);
        }
        internalCall.peer.addStream(self.getLocalStream());
        internalCall.localStream = self.getLocalStream();
    };

    // Native implementation lies on webRtcAdaptor.js
    self.disposeStreamRenderer = function(container){
        if(container){
            container.innerHTML = "";
        }
    };

    /**
     * Send DTMF tone
     * Native implementation lies on webRtcAdaptor.js
     *
     * @ignore
     * @name rtc.sendDTMF
     * @function
     * @param {Object} call internalCall
     * @param {String} tone DTMF tone
     */
    self.sendDTMF = function (call, tone) {
        logger.info("sending DTMF tone : " + tone);

        if(!call.dtmfSender) {
            var localAudioTrack = self.getLocalAudioTrack(call.peer);
            if(!localAudioTrack) {
                return;
            }
            call.dtmfSender = call.peer.createDTMFSender(localAudioTrack);
            if(!call.dtmfSender) {
                return;
            }
        }

        if (call.dtmfSender.canInsertDTMF === true) {
            call.dtmfSender.insertDTMF(tone, 400);
        }
        else {
            logger.error("Failed to execute 'insertDTMF' on 'RTCDTMFSender': The 'canInsertDTMF' attribute is false: this sender cannot send DTMF");
        }
    };

    logger.debug('WebRtcAdaptor initialized');
};

var WebRtcAdaptor = function(_super, _decorator, _model) {
    return new WebRtcAdaptorImpl(_super, _decorator, _model, logManager);
};

if (__testonly__) { __testonly__.WebRtcAdaptor = WebRtcAdaptor; }

var WebRtcPluginAdaptorImpl = function(_super, _decorator, _model, _logManager) {
    var self = this,
            logger = _logManager.getLogger("WebRtcPluginAdaptorImpl");

    logger.debug('WebRtcPluginAdaptor initializing');

    utils.compose(_super, self);
    utils.compose(_model, self);

    self.setPluginEnabled(true);

    // Enabler implementation lies on webRtcPluginAdaptor.js
    // initEnablerMedia
    self.initMedia = function(onSuccess, onFailure, options) {
        var mainContainer = document.body,
                rtcPlugin = {},
                verifyPlugin = true,
                mediaErrors = fcs.call.MediaErrors,
                onloadParam,
                size = "1px",
                pluginid = "fcsPlugin",
                applicationType = "application/x-gcfwenabler",
                configuredPluginVersion = self.getPluginVersion(),
                currentPluginVersion,
                currentPluginVersionString;

        logger.debug("Configured plugin version: " + configuredPluginVersion.major + "." + configuredPluginVersion.minor + "." + configuredPluginVersion.current_revision);

        if(options) {
            if (options.localVideoContainer) {
                self.setLocalVideoContainer(options.localVideoContainer);
            }

            if (options.remoteVideoContainer) {
                self.setRemoteVideoContainer(options.remoteVideoContainer);
            }

            if (options.videoContainer) {
                self.setDefaultVideoContainer(options.videoContainer);
            }

            if (options.pluginLogLevel) {
                self.setLogLevel(options.pluginLogLevel);
            }

            if (options.language) {
                self.setLanguage(options.language);
            }
        }
        //Callback for when the plugin is loaded
        self.onFCSPLoaded = function() {

            self.setRtcLibrary(_decorator(rtcPlugin));
            self.getRtcLibrary().checkMediaSourceAvailability(function mediaSourceCallback(mediaSourceInfo) {
                self.setMediaSources(mediaSourceInfo);
            });

            currentPluginVersion = self.getRtcLibrary().getCurrentPluginVersionObject();
            currentPluginVersionString = self.getRtcLibrary().getVersion();
            // prevent multiple init calls
            if (self.isInitialized() || !verifyPlugin) {
                return;
            }
            verifyPlugin = false;
            logger.debug("Plugin callback");

            fcs.setPluginVersion(currentPluginVersionString);
            logger.debug("Installed plugin version: " + currentPluginVersionString);

            if ((currentPluginVersionString.length < 1) ||
                    (currentPluginVersion.major !== configuredPluginVersion.major ||
                            currentPluginVersion.minor !== configuredPluginVersion.minor) ||
                    (currentPluginVersion.revision < configuredPluginVersion.min_revision) ||
                    (currentPluginVersion.revision === configuredPluginVersion.min_revision &&
                 currentPluginVersion.build < configuredPluginVersion.min_build) ) {

                logger.debug("Plugin version not supported");
                utils.callFunctionIfExist(onFailure, mediaErrors.WRONG_VERSION);
            } else {
                self.setInitialized(true);
                if ((currentPluginVersion.revision < configuredPluginVersion.current_revision) ||
                        (currentPluginVersion.revision === configuredPluginVersion.current_revision &&
                     currentPluginVersion.build < configuredPluginVersion.current_build) ) {

                    logger.debug("New plugin version warning");
                    utils.callFunctionIfExist(onFailure, mediaErrors.NEW_VERSION_WARNING);
                } else {
                    utils.callFunctionIfExist(onSuccess,
                                               { "pluginVersion": rtcPlugin.version } );
                }

                self.getRtcLibrary().setLang(self.getLanguage());
            }

            self.setLocalStream(null);
            self.getRtcLibrary().checkMediaSourceAvailability();
        };

        // only check if the function exists, not its type, because in IE it is "object" (host object)
        if (typeof mainContainer.appendChild === 'undefined') {
            logger.debug("Could not inject plugin in container");
            utils.callFunctionIfExist(onFailure, mediaErrors.OPTIONS);
            return;
        }

        rtcPlugin = document.createElement('object');
        onloadParam = document.createElement('param');
        onloadParam.setAttribute("name", "onload");
        onloadParam.setAttribute("value", "onFCSPLoaded");
        rtcPlugin.appendChild(onloadParam);

        rtcPlugin.id = pluginid;
        rtcPlugin.width = rtcPlugin.height = size;

        // Order matters for the following:
        // For IE you need to append first so the dom is available when IE loads the plugin, which happens when the type is set.
        // For FF you need to set the type and then append or the plugin won't load.
        // Chrome seems happy either way.
        try {
            if (navigator.appName === 'Microsoft Internet Explorer') {
                mainContainer.appendChild(rtcPlugin);
                rtcPlugin.type = applicationType;
            } else {
                rtcPlugin.type = applicationType;
                mainContainer.appendChild(rtcPlugin);
            }
        } catch (e) {
            verifyPlugin = false;
            utils.callFunctionIfExist(onFailure, mediaErrors.NOT_FOUND);
        }

        if (verifyPlugin) {
            if (typeof document.getElementById(pluginid).createPeerConnection !== 'undefined') {
                self.onFCSPLoaded();
            } else {
                //if the plugin is not initialized within 7 sec fail
                setTimeout(function() {
                    // for createPeerConnection, only check if it exists. It is "function" in FireFox and "object" in Chrome and IE
                    if (!self.isInitialized()) {
                        if (typeof document.getElementById(pluginid).createPeerConnection === 'undefined') {
                            utils.callFunctionIfExist(onFailure, mediaErrors.NOT_FOUND);
                        } else {
                            self.onFCSPLoaded();
                        }
                    }
                }, 7000);
            }
        }
    };

    // Enabler implementation lies on webRtcPluginAdaptor.js
    self.getUserMedia = function(onSuccess, onFailure) {
        self.getRtcLibrary().checkMediaSourceAvailability(function getUserMediaCallback(mediaSourceInfo) {
            var video_constraints, mediaInfo;
            logger.debug("Plugin version:" + self.getRtcLibrary().version);
            if (mediaSourceInfo) {
                self.setVideoSourceAvailable(mediaSourceInfo.videoSourceAvailable);
                self.setAudioSourceAvailable(mediaSourceInfo.audioSourceAvailable);
            }
            if (self.getMediaVideo() && self.getVideoSourceAvailable()) {
                video_constraints = {
                    mandatory: {
                        "maxWidth": self.getVideoWidth(),
                        "maxHeight": self.getVideoHeight()
                    }
                };
            } else {
                video_constraints = false;
            }

            if (mediaSourceInfo) {
                if (mediaSourceInfo.localStream) {
                    mediaInfo = {
                        "audio": self.getMediaAudio(),
                        "video": self.getMediaVideo() && self.getVideoSourceAvailable()
                    };
                    utils.callFunctionIfExist(onSuccess, mediaInfo);
                    return;
                }
            }

            self.getRtcLibrary().getUserMedia({
                audio: self.getMediaAudio(),
                video: video_constraints
            }, function getUserMediaSuccessCallback(stream) {
                logger.debug("user has granted access to local media.");
                self.setLocalStream(stream);

                self.setInitialized(true);
                mediaInfo = {
                    "audio": self.getMediaAudio(),
                    "video": self.getMediaVideo() && self.getVideoSourceAvailable()
                };
                utils.callFunctionIfExist(onSuccess, mediaInfo);
            }, function getUserMediaFailureCallback(error) {
                logger.debug("Failed to get access to local media. Error code was " + error.code);
                utils.callFunctionIfExist(onFailure, fcs.call.MediaErrors.NOT_ALLOWED);
            });
        });
    };


    /*
     * Add Candidates
     * Enabler implementation lies on webRtcPluginAdaptor.js
     * @param {type} call
     */
    self.addCandidates = function(call) {
        var ma_indx, mv_indx, ma_str = "", mv_str = "", c_indx, candidate, arr, i, reg = /\r\n|\r|\n/;

        ma_indx = call.sdp.indexOf(CONSTANTS.SDP.M_LINE + CONSTANTS.STRING.AUDIO, 0);
        mv_indx = call.sdp.indexOf(CONSTANTS.SDP.M_LINE + CONSTANTS.STRING.VIDEO, 0);

        if (ma_indx !== -1 && mv_indx !== -1) {
            if (ma_indx < mv_indx) {
                ma_str = call.sdp.substring(ma_indx, mv_indx);
                mv_str = call.sdp.substring(mv_indx);
            } else {
                mv_str = call.sdp.substring(mv_indx, ma_indx);
                ma_str = call.sdp.substring(ma_indx);
            }
        } else if (ma_indx !== -1) {
            ma_str = call.sdp.substring(ma_indx);
        } else if (mv_indx !== -1) {
            mv_str = call.sdp.substring(mv_indx);
        }

        if (ma_str !== "") {
            c_indx = ma_str.indexOf("a=candidate", 0);
            if (c_indx !== -1) {
                ma_str = ma_str.substring(c_indx);
                arr = ma_str.split(reg);
                i = 0;
                while (arr[i] && arr[i].indexOf("a=candidate") !== -1) {
                    candidate = self.getRtcLibrary().createRTCIceCandidate(arr[i], CONSTANTS.STRING.AUDIO, 0);
                    call.peer.addIceCandidate(candidate);
                    i++;
                }
            }
        }

        if (mv_str !== "") {
            c_indx = mv_str.indexOf("a=candidate", 0);
            if (c_indx !== -1) {
                mv_str = mv_str.substring(c_indx);
                arr = mv_str.split(reg);
                i = 0;
                while (arr[i] && arr[i].indexOf("a=candidate") !== -1) {
                    candidate = self.getRtcLibrary().createRTCIceCandidate(arr[i], CONSTANTS.STRING.VIDEO, 1);
                    call.peer.addIceCandidate(candidate);
                    i++;
                }

            }
        }
    };

    /*
     * Enabler implementation lies on webRtcPluginAdaptor.js
     * createEnablerOffer to be used when the enabler plugin is enabled.
     */
    self.createOffer = function(call, successCallback, failureCallback, sendInitialVideo) {
        logger.debug("createOffer: sendInitialVideo= " + sendInitialVideo + " state= " + call.peer.signalingState);
        var peer = call.peer, newSdp;

        peer.addStream(self.getLocalStream());
        call.localStream = self.getLocalStream();

        peer.createOffer(function createOfferSuccessCallback(oSdp) {
            sendInitialVideo = sendInitialVideo && self.getVideoSourceAvailable();
            newSdp = sdpParser.getSdpFromObject(oSdp);
            oSdp = null;
            if(sendInitialVideo){
                newSdp = sdpParser.updateVideoSdpDirection(newSdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE);
            } else {
                newSdp = sdpParser.updateVideoSdpDirection(newSdp, CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY);
            }

            newSdp = sdpParser.deleteCryptoZeroFromSdp(newSdp);
            newSdp = sdpParser.performVP8RTCPParameterWorkaround(newSdp);
            newSdp = sdpParser.updateAudioCodec(newSdp);
            newSdp = sdpParser.removeG722Codec(newSdp);

            newSdp = sdpParser.deleteCryptoFromSdp(newSdp, self.isDtlsEnabled());
            newSdp = sdpParser.setMediaActPass(newSdp, self.isDtlsEnabled());

            newSdp = sdpParser.fixLocalTelephoneEventPayloadType(call, newSdp);
            newSdp = sdpParser.replaceOpusCodec(newSdp);

            self.muteOnHold(call,false);
            call.offer = self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.OFFER, newSdp);
            peer.setLocalDescription(
                    call.offer,
                function createOfferSetLocalDescriptionSuccessCallback(){
                        //Due to stun requests, successCallback will be called by onNativeIceCandidate()
                        webRtcAdaptorUtils.setLocalStreamVideoSendStatus(call, sendInitialVideo);
                    },
                    function createOfferSetLocalDescriptionFailureCallback(error) {
                        logger.error("createOffer: setLocalDescription failed : " + error);
                        utils.callFunctionIfExist(failureCallback, "createOffer: setLocalDescription failed");
                    }
            );

        },function createOfferFailureCallback(error){
            logger.error("createOffer: createOffer failed!! " + error);
            utils.callFunctionIfExist(failureCallback);
        },
                {
                    'mandatory': {
                'OfferToReceiveAudio':self.getMediaAudio(),
                'OfferToReceiveVideo':self.getMediaVideo()
                    }
                });
    };

    /*
     * createEnablerAnswer to be used when the enabler plugin is enabled
     * Enabler implementation lies on webRtcPluginAdaptor.js
     */
    self.createAnswer = function(call, successCallback, failureCallback, isVideoEnabled) {
        logger.debug("createAnswer: isVideoEnabled= " + isVideoEnabled + " state= " + call.peer.signalingState);
        var peer = call.peer, newSdp, newOffer;

        call.sdp = sdpParser.performVP8RTCPParameterWorkaround(call.sdp);
        call.sdp = sdpParser.checkSupportedVideoCodecs(call.sdp, null);
        call.sdp = sdpParser.removeRTXCodec(call.sdp);
        call.sdp = sdpParser.removeG722Codec(call.sdp);
        call.sdp = sdpParser.performG722ParameterWorkaround(call.sdp);
        call.sdp = sdpParser.fixRemoteTelephoneEventPayloadType(call, call.sdp);
        call.sdp = sdpParser.changeDirection(call.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE, CONSTANTS.STRING.AUDIO);
        call.sdp = sdpParser.setMediaActPass(call.sdp, self.isDtlsEnabled());
        call.sdp = sdpParser.deleteFingerprintOrCrypto(call.sdp, self.isDtlsEnabled());

        if (!sdpParser.isSdpVideoSendEnabled(call.sdp)) {
            // delete ssrc only from video, keep audio ssrc to hear audio
            call.sdp = sdpParser.deleteInactiveVideoSsrc(call.sdp);
        }

        peer.setRemoteDescription(
                self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.OFFER, call.sdp),
                function createAnswerSetRemoteDescriptionSuccessCallback(){
                    peer.addStream(self.getLocalStream());
                    call.localStream = self.getLocalStream();
                    call.remoteVideoState = sdpParser.getVideoSdpDirection(call.sdp);

                    webRtcAdaptorUtils.callSetReceiveVideo(call);
                    self.addCandidates(call);

                    // set answer SDP to localDescriptor for the offer
                    peer.createAnswer(peer.remoteDescription,
                            function createAnswerSuccessCallback(oSdp) {
                                newSdp = sdpParser.getSdpFromObject(oSdp);
                                oSdp = null;
                                isVideoEnabled = isVideoEnabled && self.getVideoSourceAvailable() && sdpParser.isSdpHasVideo(call.sdp);
                                webRtcAdaptorUtils.setLocalStreamVideoSendStatus(call, isVideoEnabled);

                                if (isVideoEnabled) {
                                    if (sdpParser.isSdpVideoSendEnabled(call.sdp)) {
                                        newSdp = sdpParser.updateVideoSdpDirection(newSdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE);
                                    } else {
                                        newSdp = sdpParser.updateVideoSdpDirection(newSdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_ONLY);
                                    }
                                } else {
                                    if (sdpParser.isSdpVideoSendEnabled(call.sdp)) {
                                        newSdp = sdpParser.updateVideoSdpDirection(newSdp, CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY);
                                    } else {
                                        newSdp = sdpParser.updateVideoSdpDirection(newSdp, CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE);
                                    }
                                }

                                logger.debug("doAnswer(plugin) - isSdpEnabled audio : " + sdpParser.isAudioSdpEnabled(newSdp));
                                logger.debug("doAnswer(plugin) - isSdpEnabled video : " + sdpParser.isVideoSdpEnabled(newSdp));

                                if (sdpParser.isSdpHasAudio(newSdp) || sdpParser.isSdpHasVideo(newSdp)) {
                                    newSdp = sdpParser.performVP8RTCPParameterWorkaround(newSdp);

                                    newSdp = sdpParser.setMediaPassive(newSdp, self.isDtlsEnabled());

                                    newSdp = sdpParser.fixLocalTelephoneEventPayloadType(call, newSdp);

                                    newOffer = self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.ANSWER, newSdp);
                                    call.answer = newOffer;
                                    self.muteOnHold(call, false);
                                    peer.setLocalDescription(newOffer,
                                            function createAnswerSetLocalDescriptionSuccessCallback() {
                                                //Due to stun requests, successCallback will be called by onNativeIceCandidate()
                                                call.videoOfferSent = sdpParser.isSdpHasVideo(newSdp);
                                            },
                                            function createAnswerSetLocalDescriptionFailureCallback(e) {
                                                logger.error("createAnswer: setLocalDescription failed : " + e);
                                                utils.callFunctionIfExist(failureCallback, "createAnswer setLocalDescription failed");
                                            });
                                } else {
                                    logger.error("createrAnswer: createAnswer failed!!");
                                    utils.callFunctionIfExist(failureCallback, "No codec negotiation");
                                }
                            }, function createAnswerFailureCallback(e) {
                        logger.error("createAnswer: failed!!" + e);
                        utils.callFunctionIfExist(failureCallback, "Session cannot be created ");
                    },
                            {
                                'mandatory': {
                                    'OfferToReceiveAudio': self.getMediaAudio(),
                                    'OfferToReceiveVideo': self.getMediaVideo()
                                }
                            });
                }
            , function createAnswerSetRemoteDescriptionFailureCallback(e){
                logger.error("createAnswer setRemoteDescription failed : " + e);
            });
    };

    /*
     * Enabler implementation lies on webRtcPluginAdaptor.js
     * createEnablerUpdate to be used when the video start or stop
     */
    self.createUpdate = function(call, successCallback, failureCallback, isVideoStart) {
        logger.debug("createEnablerUpdate: isVideoStart= " + isVideoStart + " state= " + call.peer.signalingState);
        var localSdp, isIceLite;

        call.stableRemoteSdp = call.peer.remoteDescription.sdp;
        call.stableLocalSdp = call.peer.localDescription.sdp;

        localSdp = sdpParser.getSdpFromObject(call.peer.localDescription);
        isIceLite = call.isIceLite;
        localSdp = sdpParser.incrementVersion(localSdp);
        localSdp = sdpParser.deleteCryptoFromSdp(localSdp, self.isDtlsEnabled());
        localSdp = sdpParser.setMediaActPass(localSdp, self.isDtlsEnabled());
        localSdp = sdpParser.fixLocalTelephoneEventPayloadType(call, localSdp);
        webRtcAdaptorUtils.setLocalStreamVideoSendStatus(call, isVideoStart);

        // for ice-lite scenario:
        // if there is no video m-line in the localSdp, create new offer to start the video
        // if there is video m-line and video is allocated for the first time, only replace the stream
        // for peer-to-peer scenario:
        // if video is allocated for the first time, create new offer

        if (isIceLite) {
            if (sdpParser.isSdpHasVideo(localSdp)) {
                self.createUpdateWithSetLocalDescription(call, successCallback, failureCallback, isVideoStart, localSdp);
            } else {
                self.createUpdateWithCreateOffer(call, successCallback, failureCallback, isVideoStart, localSdp, isIceLite);
            }
        } else {
            if (call.videoOfferSent) {
                self.createUpdateWithSetLocalDescription(call, successCallback, failureCallback, isVideoStart, localSdp);
            } else {
                self.createUpdateWithCreateOffer(call, successCallback, failureCallback, isVideoStart, localSdp, isIceLite);
            }
        }
    };

    /*
     * Enabler implementation lies on webRtcPluginAdaptor.js
     * createEnablerHoldUpdate to be used when the enabler plugin is enabled
     */
    self.createHoldUpdate = function(call, hold, remote_hold_status, successCallback, failureCallback) {
        logger.debug("createHoldUpdate: local hold= " + hold + " remote hold= " + remote_hold_status + " state= " + call.peer.signalingState);
        var peer = call.peer,
                audioDirection,
                videoDirection,
                localSdp,
                externalSdp,
                tempSdp,
                successSdp,
                muteCall,
                obj;

        call.stableRemoteSdp = peer.remoteDescription.sdp;
        call.stableLocalSdp = peer.localDescription.sdp;

        tempSdp = sdpParser.incrementVersion(call.peer.localDescription.sdp);

        tempSdp = sdpParser.setMediaActPass(tempSdp, self.isDtlsEnabled());

        //two sdp-s are created here
        //one is to be used by rest-request (externalSdp)
        //one is to set the audio-video direction of the local call (localSdp)
        //this is needed in order to adapt to the rfc (needs sendrecv to sendonly transition)
        //and to the plugin (needs inactive to mute audio and video connection)
        externalSdp = tempSdp;
        localSdp = tempSdp;

        if (hold || remote_hold_status) {
            audioDirection = sdpParser.getAudioSdpDirection(externalSdp);
            if (audioDirection === CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE) {
                externalSdp = sdpParser.updateAudioSdpDirection(externalSdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_ONLY);
            } else {
                if (!hold && remote_hold_status) {
                    externalSdp = sdpParser.updateAudioSdpDirection(externalSdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE);
                } else {
                    externalSdp = sdpParser.updateAudioSdpDirection(externalSdp, CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE);
                }
            }
            videoDirection = sdpParser.getVideoSdpDirection(externalSdp);
            if (videoDirection === CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE) {
                externalSdp = sdpParser.updateVideoSdpDirection(externalSdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_ONLY);
            } else {
                if (!hold && remote_hold_status) {
                    externalSdp = sdpParser.updateVideoSdpDirection(externalSdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE);
                } else {
                    externalSdp = sdpParser.updateVideoSdpDirection(externalSdp, CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE);
                }
            }
            localSdp = sdpParser.updateAudioSdpDirection(externalSdp, CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE);
            localSdp = sdpParser.updateVideoSdpDirection(localSdp, CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE);
            muteCall = true;

            //Ersan - Multiple Call Plugin Issue Tries
            //
            //localStream.stop();

            //if (defaultVideoContainer) {
            //    if(defaultVideoContainer.lastElementChild) {
            //        disposeStreamRenderer(defaultVideoContainer.lastElementChild);
            //    }
            //} else if (localVideoContainer) {
            //    disposeStreamRenderer(localVideoContainer);
            //}

        } else {
            externalSdp = sdpParser.updateAudioSdpDirection(externalSdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE);
            if (webRtcAdaptorUtils.callCanLocalSendVideo(call)) {
                externalSdp = sdpParser.updateVideoSdpDirection(externalSdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE);
                webRtcAdaptorUtils.setLocalStreamVideoSendStatus(call, true);
                //addLocalStream(call);     //Ersan - Multiple Call Plugin Issue Tries
            } else {
                externalSdp = sdpParser.updateVideoSdpDirection(externalSdp, CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY);
                webRtcAdaptorUtils.setLocalStreamVideoSendStatus(call, false);
            }
            localSdp = externalSdp;
            muteCall = false;
        }

        localSdp = sdpParser.fixLocalTelephoneEventPayloadType(call, localSdp);

        obj = self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.OFFER, localSdp);

        peer.setLocalDescription(obj,
                function createHoldUpdateSetLocalDescriptionSuccessCallback() {
                    logger.debug("createHoldUpdate: setLocalDescription success");
                    successSdp = sdpParser.updateH264Level(externalSdp);
                    self.muteOnHold(call, muteCall);
                    utils.callFunctionIfExist(successCallback, externalSdp);
                },
                function createHoldUpdateSetLocalDescriptionFailureCallback(e) {
                    logger.error("createHoldUpdate: setLocalDescription failed : " + e);
                    utils.callFunctionIfExist(failureCallback);
                }
        );
    };

    /*
     * Enabler implementation lies on webRtcPluginAdaptor.js
     * processEnabler30Update to be used when the enabler plugin is enabled. (based on processEnabler30Update)
     */
    self.processUpdate = function(call, successCallback, failureCallback, local_hold_status) {
        logger.debug("processUpdate: state= " + call.peer.signalingState);
        var peer = call.peer, localSdp, successSdp, remoteAudioState, remoteVideoState, newPeerCreated = false, peerRemoteSdp,
                remoteDescObj, peerLocalSdp, remoteVideoDirection, callSdpWithNoSsrc;

        call.stableRemoteSdp = peer.remoteDescription.sdp;
        call.stableLocalSdp = peer.localDescription.sdp;

        // Meetme workaround. This workaround is added into native function
        call.sdp = sdpParser.addSdpMissingCryptoLine(call.sdp);
        call.sdp = sdpParser.removeSdpPli(call.sdp);
        call.sdp = sdpParser.removeG722Codec(call.sdp);
        call.sdp = sdpParser.performG722ParameterWorkaround(call.sdp);
        call.sdp = sdpParser.performVP8RTCPParameterWorkaround(call.sdp);
        call.sdp = sdpParser.removeRTXCodec(call.sdp);
        call.sdp = sdpParser.fixRemoteTelephoneEventPayloadType(call, call.sdp);
        call.sdp = sdpParser.checkAndRestoreICEParams(call.sdp, call.peer.localDescription.sdp);

        remoteVideoDirection = sdpParser.getVideoSdpDirection(call.sdp);

        self.setMediaVideo(sdpParser.isSdpHasVideo(call.sdp));
        if ((remoteVideoDirection === CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE) &&
                (call.currentState === "COMPLETED"))
        {
            switch (call.remoteVideoState) {
                case CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE:
                    call.sdp = sdpParser.updateVideoSdpDirection(call.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE);
                    break;
                case CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY:
                    call.sdp = sdpParser.updateVideoSdpDirection(call.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE);
                    break;
                case CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE:
                    call.sdp = sdpParser.updateVideoSdpDirection(call.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY);
                    break;
            }
        }

        if (local_hold_status) {
            call.sdp = sdpParser.updateAudioSdpDirectionToInactive(call.sdp);
            call.sdp = sdpParser.updateVideoSdpDirectionToInactive(call.sdp);
        }

        call.sdp = sdpParser.changeDirection(call.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_ONLY, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE, CONSTANTS.STRING.VIDEO);
        webRtcAdaptorUtils.callSetReceiveVideo(call);

        if (peer.signalingState === CONSTANTS.WEBRTC.RTC_SIGNALING_STATE.HAVE_LOCAL_OFFER) {
            call.sdp = sdpParser.checkSupportedVideoCodecs(call.sdp, sdpParser.getSdpFromObject(call.peer.localDescription));

            call.sdp = sdpParser.setMediaPassive(call.sdp, self.isDtlsEnabled());

            remoteDescObj = self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.ANSWER, call.sdp);
            peer.setRemoteDescription(
                    remoteDescObj,
                    function processUpdateSetRemoteDescriptionSuccessCallback() {
                        call.remoteVideoState = sdpParser.getVideoSdpDirection(call.sdp);
                        self.addCandidates(call);
                        utils.callFunctionIfExist(successCallback, call.sdp);
                        call.successCallback = null;
                    },
                    function processUpdateSetRemoteDescriptionFailureCallback(e) {
                        logger.debug("processUpdate: setRemoteDescription failed!!" + e);
                        utils.callFunctionIfExist(failureCallback, "processUpdate: setRemoteDescription failed!!");
                    });
        } else {
            call.sdp = sdpParser.checkSupportedVideoCodecs(call.sdp, null);
            //this part is a work-around for webrtc bug
            //set remote description with inactive media lines first.
            //then set remote description with original media lines.

            //keep original values of remote audio and video states
            remoteAudioState = sdpParser.getAudioSdpDirection(call.sdp);
            remoteVideoState = sdpParser.getVideoSdpDirection(call.sdp);

            if (sdpParser.getVideoSdpDirection(call.sdp) === CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE ||
                    sdpParser.getVideoSdpDirection(call.sdp) === CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY)
            {
                call.sdp = sdpParser.deleteInactiveVideoSsrc(call.sdp);
            }
            //set media lines with sendonly state for work-around
            call.sdp = sdpParser.updateAudioSdpDirectionToInactive(call.sdp);
            call.sdp = sdpParser.updateVideoSdpDirectionToInactive(call.sdp);

            call.sdp = sdpParser.setMediaActPass(call.sdp, self.isDtlsEnabled());
            // delete all ssrc lines from the sdp before setting first remote description
            // set second remote description with all ssrc lines included
            peerRemoteSdp = self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.OFFER, call.prevRemoteSdp);
            peerLocalSdp = peer.localDescription.sdp;

            if (self.createNewPeerForCallIfIceChangedInRemoteSdp(call, call.sdp, call.prevRemoteSdp)) {
                peer = call.peer;
                newPeerCreated = true;
            }
            callSdpWithNoSsrc = sdpParser.deleteSsrcFromSdp(call.sdp);

            remoteDescObj = self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.OFFER, callSdpWithNoSsrc);
            peer.setRemoteDescription(remoteDescObj,
                    function processUpdateWorkaroundSetRemoteDescriptionSuccessCallback() {
                        logger.debug("processUpdate: workaround setRemoteDescription success");

                        //restore original values
                        call.sdp = sdpParser.updateAudioSdpDirection(call.sdp, remoteAudioState);
                        call.sdp = sdpParser.updateVideoSdpDirection(call.sdp, remoteVideoState);

                        remoteDescObj = self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.OFFER, call.sdp);

                        peer.setRemoteDescription(remoteDescObj,
                                function processUpdateSetRemoteDescriptionSuccessCallback() {
                                    logger.debug("processUpdate: setRemoteDescription success");
                                    call.remoteVideoState = sdpParser.getVideoSdpDirection(call.sdp);
                                    self.addCandidates(call);

                                    peer.createAnswer(peer.remoteDescription,
                                            function processUpdateCreateAnswerSuccessCallback(obj) {
                                                logger.debug("processUpdate: isSdpEnabled audio= " + sdpParser.isAudioSdpEnabled(obj.sdp));
                                                logger.debug("processUpdate: isSdpEnabled video= " + sdpParser.isVideoSdpEnabled(obj.sdp));

                                                if (sdpParser.isAudioSdpEnabled(obj.sdp) || sdpParser.isVideoSdpEnabled(obj.sdp)) {
                                                    if (sdpParser.getAudioSdpDirection(call.sdp) === CONSTANTS.WEBRTC.MEDIA_STATE.SEND_ONLY) {
                                                        logger.debug("processUpdate: audio sendonly -> recvonly");
                                                        obj.audioDirection = CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY;
                                                    }

                                                    if (sdpParser.getAudioSdpDirection(call.sdp) === CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE) {
                                                        obj.audioDirection = CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE;
                                                    }

                                                    if (sdpParser.getVideoSdpDirection(call.sdp) === CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE) {
                                                        obj.videoDirection = CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE;
                                                    }

                                                    if (sdpParser.getVideoSdpDirection(call.sdp) === CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY) {
                                                        if (webRtcAdaptorUtils.callCanLocalSendVideo(call)) {
                                                            obj.videoDirection = CONSTANTS.WEBRTC.MEDIA_STATE.SEND_ONLY;
                                                        } else {
                                                            obj.videoDirection = CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE;
                                                        }
                                                    } else if (webRtcAdaptorUtils.callCanLocalSendVideo(call)) {
                                                        obj.videoDirection = CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE;
                                                    } else {
                                                        obj.videoDirection = CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY;
                                                    }

                                                    //TODO: Since there is no setter method for obj.sdp from the plugin side,
                                                    //      we create a temporary local variable and pass obj.sdp's value into it.
                                                    //      Rewrite the below part of code when the setter method is applied to the plugin side
                                                    localSdp = sdpParser.getSdpFromObject(obj);
                                                    obj = null;
                                                    localSdp = sdpParser.updateVersion(peerLocalSdp, localSdp);
                                                    localSdp = sdpParser.performVP8RTCPParameterWorkaround(localSdp);

                                                    localSdp = sdpParser.checkIceParamsLengths(localSdp, call.sdp);
                                                    localSdp = sdpParser.setMediaPassive(localSdp, self.isDtlsEnabled());

                                                    localSdp = sdpParser.fixLocalTelephoneEventPayloadType(call, localSdp);
                                                    if (newPeerCreated) {
                                                        localSdp = sdpParser.copyCandidatesToTheNewLocalSdp(peerLocalSdp, localSdp);
                                                        newPeerCreated = false;
                                                    }

                                                    call.answer = self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.ANSWER, localSdp);

                                                    peer.setLocalDescription(call.answer,
                                                            function processUpdateSetLocalDescriptionSuccessCallback() {
                                                                if (sdpParser.isMediaPortReady(localSdp)) {
                                                                    logger.debug("processUpdate: setLocalDescription success");
                                                                    successSdp = sdpParser.updateH264Level(localSdp);

                                                                    if (local_hold_status) {
                                                                        successSdp = sdpParser.updateAudioSdpDirection(successSdp, CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE);
                                                                        successSdp = sdpParser.updateVideoSdpDirection(successSdp, CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE);
                                                                    }

                                                                    utils.callFunctionIfExist(successCallback, successSdp);
                                                                    call.successCallback = null;
                                                                    call.answer = null;     // ABE-1328
                                                                }
                                                            },
                                                            function processUpdateSetLocalDescriptionFailureCallback(e) {
                                                                logger.debug("processUpdate: setLocalDescription failed: " + e);
                                                                utils.callFunctionIfExist(failureCallback, "processUpdate: setlocalDescription failed!!");
                                                                call.answer = null;     // ABE-1328
                                                            });
                                                } else {
                                                    logger.debug("processUpdate: createAnswer failed!!");
                                                    utils.callFunctionIfExist(failureCallback, "No codec negotiation");

                                                }
                                            },
                                            function processUpdateCreateAnswerFailureCallback(e) {
                                                logger.debug("processUpdate: createAnswer failed!! " + e);
                                                utils.callFunctionIfExist(failureCallback, "Session cannot be created");
                                            },
                                            {
                                                'mandatory': {
                                                    'OfferToReceiveAudio': self.getMediaAudio(),
                                                    'OfferToReceiveVideo': self.getMediaVideo()
                                                }
                                            }
                                    );
                                },
                                function processUpdateSetRemoteDescriptionSuccessCallback(e) {
                                    logger.debug("processUpdate: setRemoteDescription failed: " + e);
                                    utils.callFunctionIfExist(failureCallback, "processUpdate: setRemoteDescription failed!!");
                                });
                    },
                    function processUpdateWorkaroundSetRemoteDescriptionFailureCallback(e) {
                        logger.debug("processUpdate: workaround setRemoteDescription failed!!" + e);
                        utils.callFunctionIfExist(failureCallback, "processUpdate: workaround setRemoteDescription failed!!");
                    }
            );
        }
    };

    /*
     * Enabler implementation lies on webRtcPluginAdaptor.js
     * processEnabler30Answer to be used when the enabler plugin is enabled
     */
    self.processAnswer = function(call, onSuccess, onFail) {
        logger.debug("processAnswer: state= " + call.peer.signalingState);

        var restoreSdpOnSuccess, audioWorkaroundOnSuccess, onSuccessAfterWorkarounds,
                remoteVideoDirection, localVideoDirection;

        onSuccessAfterWorkarounds = function() {
            call.remoteVideoState = sdpParser.getVideoSdpDirection(call.sdp);
            call.videoOfferSent = sdpParser.isSdpHasVideo(call.sdp);
            self.addCandidates(call);
            utils.callFunctionIfExist(onSuccess);
        };

        call.sdp = sdpParser.checkSupportedVideoCodecs(call.sdp, sdpParser.getSdpFromObject(call.peer.localDescription));
        call.sdp = sdpParser.performVideoPortZeroWorkaround(call.sdp);
        call.sdp = sdpParser.removeSdpPli(call.sdp);
        call.sdp = sdpParser.removeG722Codec(call.sdp);
        call.sdp = sdpParser.performG722ParameterWorkaround(call.sdp);
        call.sdp = sdpParser.performVP8RTCPParameterWorkaround(call.sdp);
        call.sdp = sdpParser.performVP8BandwidthWorkaround(call.sdp);
        call.sdp = sdpParser.removeRTXCodec(call.sdp);
        call.sdp = sdpParser.fixRemoteTelephoneEventPayloadType(call, call.sdp);

        webRtcAdaptorUtils.callSetReceiveVideo(call);

        remoteVideoDirection = sdpParser.getVideoSdpDirection(call.sdp);
        localVideoDirection = sdpParser.getVideoSdpDirection(sdpParser.getSdpFromObject(call.peer.localDescription));

        // this is needed for buggy webrtc api. when term answers with video to audio only call
        // this scenario does not work without converting to sendrecv
        logger.debug("processAnswer: ice-lite: do remote video escalation");
        call.sdp = sdpParser.changeDirection(call.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_ONLY, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE);

        if (localVideoDirection === CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY &&
                (remoteVideoDirection === CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE || remoteVideoDirection === CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY)) {

            // Audio <--> Audio : apply workaround step 1

            // delete ssrc only from video, keep audio ssrc to hear audio
            call.sdp = sdpParser.deleteInactiveVideoSsrc(call.sdp);

            self.performOrigAudioWorkaround(call, onSuccessAfterWorkarounds, onFail);

        } else if (localVideoDirection === CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE &&
                (remoteVideoDirection === CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY || remoteVideoDirection === CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE)) {

            // delete ssrc only from video, keep audio ssrc to hear audio
            call.sdp = sdpParser.deleteInactiveVideoSsrc(call.sdp);
            // Audio-Video <--> Audio : apply workaround step 1 & 2

            audioWorkaroundOnSuccess = function() {
                self.restoreActualSdp(call, onSuccessAfterWorkarounds, onFail, localVideoDirection, remoteVideoDirection);
            };

            //performEnablerOrigAudioWorkaround(call, audioWorkaroundOnSuccess, onFail);
            self.performOrigAudioWorkaround(call, onSuccessAfterWorkarounds, onFail);

        } else if (localVideoDirection === CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY &&
                (remoteVideoDirection === CONSTANTS.WEBRTC.MEDIA_STATE.SEND_ONLY || remoteVideoDirection === CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE)) {

            // Audio  <--> Audio-Video

            restoreSdpOnSuccess = function() {
                self.performVideoStartWorkaround(call, onSuccessAfterWorkarounds, onFail);
            };

            audioWorkaroundOnSuccess = function() {
                self.restoreActualSdp(call, restoreSdpOnSuccess, onFail, localVideoDirection, remoteVideoDirection);
            };

            //performEnablerOrigAudioWorkaround(call, audioWorkaroundOnSuccess, onFail);
            self.performOrigAudioWorkaround(call, restoreSdpOnSuccess, onFail);

        } else {

            // Audio-Video <--> Audio-Video
            // there is remote video, no need for orig side workaround

            call.sdp = sdpParser.setMediaPassive(call.sdp, self.isDtlsEnabled());

            call.peer.setRemoteDescription(
                    self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.ANSWER, call.sdp),
                    function() {
                        logger.debug("processAnswer: setRemoteDescription success");
                        utils.callFunctionIfExist(onSuccessAfterWorkarounds);
                    },
                    function(e) {
                        logger.debug("processAnswer: setRemoteDescription failed: " + e);
                        utils.callFunctionIfExist(onFail);
                    });
        }
    };

    /*
     * Enabler implementation lies on webRtcPluginAdaptor.js
     * performEnablerOrigAudioWorkaround - orig side can't hear audio when term side didn't start with video
     */
    self.performOrigAudioWorkaround = function(call, onSuccess, onFail) {
        logger.debug("Workaround for orig side to hear audio");

        call.sdp = sdpParser.setMediaPassive(call.sdp, self.isDtlsEnabled());

        call.peer.setRemoteDescription(
                self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.ANSWER, call.sdp), function() {
            logger.debug("performNativeOrigAudioWorkaround: setRemoteDescription success");
            utils.callFunctionIfExist(onSuccess);
        }, function(e) {
            logger.debug("performNativeOrigAudioWorkaround: setRemoteDescription failed: " + e);
            utils.callFunctionIfExist(onFail);
        });
    };

    /*
     * Enabler implementation lies on webRtcPluginAdaptor.js
     * restoreActualSdp - local and remote sdp's were manipulated to play audio. restore them here.
     */
    self.restoreActualSdp = function(call, onSuccess, onFail, localVideoDirection, remoteVideoDirection) {
        logger.debug("Restore manipulated local and remote sdp's");
        var newLocalSdp = sdpParser.getSdpFromObject(call.peer.localDescription);
        newLocalSdp = sdpParser.updateSdpDirection(newLocalSdp, CONSTANTS.STRING.VIDEO, localVideoDirection);

        newLocalSdp = sdpParser.setMediaActPass(newLocalSdp, self.isDtlsEnabled());
        call.sdp = sdpParser.setMediaPassive(call.sdp, self.isDtlsEnabled());

        newLocalSdp = sdpParser.fixLocalTelephoneEventPayloadType(call, newLocalSdp);

        // set local sdp with original direction
        call.peer.setLocalDescription(
                self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.OFFER, newLocalSdp), function() {
            logger.debug("restoreActualSdp: setLocalDescription success");
            // restore actual remote sdp
            call.sdp = sdpParser.changeDirection(call.sdp, CONSTANTS.WEBRTC.RTC_SDP_TYPE.SEND_ONLY, remoteVideoDirection, CONSTANTS.STRING.VIDEO);
            call.sdp = sdpParser.changeDirection(call.sdp, CONSTANTS.WEBRTC.RTC_SDP_TYPE.SEND_ONLY, CONSTANTS.WEBRTC.RTC_SDP_TYPE.SEND_RECEIVE, CONSTANTS.STRING.VIDEO);

            // this is required just before setRemoteDescription
            webRtcAdaptorUtils.callSetReceiveVideo(call);

            call.peer.setRemoteDescription(
                    self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.ANSWER, call.sdp), function() {
                logger.debug("restoreActualSdp: setRemoteDescription success");
                utils.callFunctionIfExist(onSuccess);
            }, function(e) {
                logger.debug("restoreActualSdp: setRemoteDescription failed: " + e);
                utils.callFunctionIfExist(onFail);
            });
        }, function(e) {
            logger.debug("restoreActualSdp: setLocalDescription failed: " + e);
            utils.callFunctionIfExist(onFail);
        });
    };

    /*
     * Enabler implementation lies on webRtcPluginAdaptor.js
     * performEnablerVideoStartWorkaround - term side cannot see orig's video
     */
    self.performVideoStartWorkaround = function(call, onSuccess, onFail) {
        var peer = call.peer, remoteAudioState, remoteVideoState,
                callSdpWithNoSsrc;

        logger.debug("Workaround to play video");

        call.sdp = sdpParser.addSdpMissingCryptoLine(call.sdp);

        remoteAudioState = sdpParser.getSdpDirectionLogging(call.sdp, CONSTANTS.STRING.AUDIO, false);
        remoteVideoState = sdpParser.getSdpDirectionLogging(call.sdp, CONSTANTS.STRING.VIDEO, false);

        call.sdp = sdpParser.updateSdpDirection(call.sdp, CONSTANTS.STRING.AUDIO, CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE);
        call.sdp = sdpParser.updateSdpDirection(call.sdp, CONSTANTS.STRING.VIDEO, CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE);

        call.sdp = sdpParser.setMediaActPass(call.sdp, self.isDtlsEnabled());

        callSdpWithNoSsrc = sdpParser.deleteSsrcFromSdp(call.sdp);

        peer.setRemoteDescription(
                self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.OFFER, callSdpWithNoSsrc), function() {
            logger.debug("performVideoStartWorkaround: first setRemoteDescription success");

            // restore original values
            call.sdp = sdpParser.updateSdpDirection(call.sdp, CONSTANTS.STRING.AUDIO, remoteAudioState);
            call.sdp = sdpParser.updateSdpDirection(call.sdp, CONSTANTS.STRING.VIDEO, remoteVideoState);

            peer.setRemoteDescription(
                    self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.OFFER, call.sdp), function() {
                logger.debug("performVideoStartWorkaround: second setRemoteDescription success");
                peer.createAnswer(peer.remoteDescription, function(obj) {
                    var localSdp = sdpParser.getSdpFromObject(obj);

                    if (sdpParser.getSdpDirectionLogging(call.sdp, CONSTANTS.STRING.AUDIO, false) === CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE) {
                        localSdp = sdpParser.updateSdpDirection(localSdp, CONSTANTS.STRING.AUDIO, CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE);
                    }

                    if (call.remoteVideoState === CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE) {
                        localSdp = sdpParser.updateSdpDirection(localSdp, CONSTANTS.STRING.VIDEO, CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE);
                    } else if (webRtcAdaptorUtils.callCanLocalSendVideo(call)) {
                        localSdp = sdpParser.updateSdpDirection(localSdp, CONSTANTS.STRING.VIDEO, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE);
                    } else {
                        localSdp = sdpParser.updateSdpDirection(localSdp, CONSTANTS.STRING.VIDEO, CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY);
                    }

                    localSdp = sdpParser.performVP8RTCPParameterWorkaround(localSdp);
                    self.fireOnStreamAddedEvent(call);

                    localSdp = sdpParser.checkAndRestoreICEParams(localSdp, call.sdp);

                    localSdp = sdpParser.setMediaPassive(localSdp, self.isDtlsEnabled());

                    localSdp = sdpParser.fixLocalTelephoneEventPayloadType(call, localSdp);

                    peer.setLocalDescription(
                            self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.ANSWER, localSdp), function() {
                        logger.debug("performVideoStartWorkaround: setlocalDescription success");
                        utils.callFunctionIfExist(onSuccess);
                    }, function(e) {
                        logger.debug("performVideoStartWorkaround: setlocalDescription failed!!" + e);
                        utils.callFunctionIfExist(onFail, "performVideoStartWorkaround: setlocalDescription failed!!");
                    });
                }, function(e) {
                    logger.debug("performVideoStartWorkaround: createAnswer failed!! " + e);
                    utils.callFunctionIfExist(onFail, "Session cannot be created");
                }, {
                    'mandatory': {
                        'OfferToReceiveAudio': self.getMediaAudio(),
                        'OfferToReceiveVideo': self.getMediaVideo()
                    }
                });
            }, function(e) {
                logger.debug("performVideoStartWorkaround: second setRemoteDescription failed!!" + e);
                utils.callFunctionIfExist(onFail, "performVideoStartWorkaround: second setRemoteDescription failed!!");
            });
        }, function(e) {
            logger.debug("performVideoStartWorkaround: first setRemoteDescription failed!!" + e);
            utils.callFunctionIfExist(onFail, "performVideoStartWorkaround: first setRemoteDescription failed!!");
        });
    };

    /*
     * Enabler implementation lies on webRtcPluginAdaptor.js
     * processPreAnswer to be used when the enabler plugin is enabled
     */
    self.processPreAnswer = function(call) {
        var ans;

        logger.debug("processPreAnswer: state= " + call.peer.signalingState);

        call.sdp = sdpParser.checkSupportedVideoCodecs(call.sdp, sdpParser.getSdpFromObject(call.peer.localDescription));
        call.sdp = sdpParser.removeG722Codec(call.sdp);
        call.sdp = sdpParser.performG722ParameterWorkaround(call.sdp);
        call.sdp = sdpParser.performVP8RTCPParameterWorkaround(call.sdp);
        call.sdp = sdpParser.removeRTXCodec(call.sdp);
        call.sdp = sdpParser.fixRemoteTelephoneEventPayloadType(call, call.sdp);

        webRtcAdaptorUtils.callSetReceiveVideo(call);

        self.addCandidates(call);
        ans = self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.PRANSWER, call.sdp);

        call.peer.setRemoteDescription(ans,
                function processPreAnswerSetRemoteDescriptionSuccessCallback() {
                    call.remoteVideoState = sdpParser.getVideoSdpDirection(call.sdp);
                    logger.debug("processPreAnswer: setRemoteDescription success");
                },
                function processPreAnswerSetRemoteDescriptionFailureCallback(e) {
                    logger.debug("processPreAnswer: setRemoteDescription failed: " + e);
                });
    };

    /*
     * Enabler implementation lies on webRtcPluginAdaptor.js
     * processEnablerRespond
     */
    self.processRespond = function(call, onSuccess, onFailure, isJoin) {
        var remoteVideoDirection;

        logger.debug("processRespond: state= " + call.peer.signalingState);

        call.sdp = sdpParser.checkSupportedVideoCodecs(call.sdp, sdpParser.getSdpFromObject(call.peer.localDescription));
        call.sdp = sdpParser.removeSdpPli(call.sdp);
        call.sdp = sdpParser.removeG722Codec(call.sdp);
        call.sdp = sdpParser.performG722ParameterWorkaround(call.sdp);
        call.sdp = sdpParser.performVP8RTCPParameterWorkaround(call.sdp);
        call.sdp = sdpParser.performVP8BandwidthWorkaround(call.sdp);
        call.sdp = sdpParser.removeRTXCodec(call.sdp);
        call.sdp = sdpParser.fixRemoteTelephoneEventPayloadType(call, call.sdp);

        remoteVideoDirection = sdpParser.getVideoSdpDirection(call.sdp);

        webRtcAdaptorUtils.callSetReceiveVideo(call);

        if ((remoteVideoDirection === CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE) && (call.currentState === "COMPLETED"))
        {
            switch (call.remoteVideoState) {
                case CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE:
                    call.sdp = sdpParser.updateSdpDirection(call.sdp, CONSTANTS.STRING.VIDEO, CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY);
                    break;
                case CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY:
                    call.sdp = sdpParser.updateSdpDirection(call.sdp, CONSTANTS.STRING.VIDEO, CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY);
                    break;
            }
        }

        call.remoteVideoState = sdpParser.getVideoSdpDirection(call.sdp);
        call.sdp = sdpParser.changeDirection(call.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_ONLY, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE, CONSTANTS.STRING.VIDEO);
        if (isJoin) {
            call.sdp = sdpParser.changeDirection(call.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE, CONSTANTS.STRING.AUDIO);
            self.muteOnHold(call, false);
        }

        if (call.peer.signalingState === CONSTANTS.WEBRTC.RTC_SIGNALING_STATE.STABLE) {
            //if we are in stable state we should not change remotedescription
            utils.callFunctionIfExist(onSuccess);
            return;
        }

        call.sdp = sdpParser.setMediaPassive(call.sdp, self.isDtlsEnabled());

        if (sdpParser.getVideoSdpDirection(call.sdp) === CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE ||
                sdpParser.getVideoSdpDirection(call.sdp) === CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY)
        {
            call.sdp = sdpParser.deleteInactiveVideoSsrc(call.sdp);
        }

        call.peer.setRemoteDescription(
                self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.ANSWER, call.sdp),
                function() {
                    logger.debug("processRespond: setRemoteDescription success");
                    var onSuccessAfterWorkaround = function() {
                        call.remoteVideoState = sdpParser.getVideoSdpDirection(call.sdp);
                        call.videoOfferSent = true;
                        self.addCandidates(call);
                        utils.callFunctionIfExist(onSuccess);
                    };
                    // utils.callFunctionIfExist(onSuccessAfterWorkaround);
                    self.performVideoStartWorkaround(call, onSuccessAfterWorkaround, onFailure);
                },
                function(e) {
                    logger.debug("processRespond: setRemoteDescription failed: " + e);
                    utils.callFunctionIfExist(onFailure);
                });
    };

    self.createReOffer = function(call, successCallback, failureCallback, iceRestart) {
        var peer = call.peer, newSdp, successSdp, answerSdp;
        peer.createOffer(
                function processSlowStartCreateOfferSuccessCallback(oSdp) {
                    newSdp = sdpParser.getSdpFromObject(oSdp);
                    oSdp = null;

                    newSdp = sdpParser.deleteCryptoZeroFromSdp(newSdp);
                    newSdp = sdpParser.performVP8RTCPParameterWorkaround(newSdp);
                    newSdp = sdpParser.updateAudioCodec(newSdp);
                    newSdp = sdpParser.removeG722Codec(newSdp);
                    newSdp = sdpParser.deleteCryptoFromSdp(newSdp, self.isDtlsEnabled());
                    newSdp = sdpParser.setMediaActPass(newSdp, self.isDtlsEnabled());
                    newSdp = sdpParser.fixLocalTelephoneEventPayloadType(call, newSdp);
                    newSdp = sdpParser.replaceOpusCodec(newSdp);

                    answerSdp = self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.OFFER, newSdp);
                    call.offer = answerSdp;

                    peer.setLocalDescription(
                            answerSdp,
                            function processSlowStartSetLocalDescriptionSuccessCallback() {
                                logger.debug("create ReOffer setLocalDescription success");
                                successSdp = sdpParser.getSdpFromObject(answerSdp);
                                if (sdpParser.isMediaPortReady(successSdp)) {
                                    if (call.successCallback) {
                                        utils.callFunctionIfExist(successCallback, successSdp);
                                        call.successCallback = null;
                                        call.offer = null;
                                        call.answer = null;
                                    }
                                }
                            },
                            function processSlowStartSetLocalDescriptionFailureCallback(error) {
                                utils.callFunctionIfExist(failureCallback, "screate ReOffer setLocalDescription failed: " + error);
                            });
                },
                function processSlowStartCreateOfferFailureCallback(error) {
                    logger.error("create ReOffer failed!! " + error);
                    utils.callFunctionIfExist(failureCallback);
                },
                {
                    'mandatory': {
                        'OfferToReceiveAudio': self.getMediaAudio(),
                        'OfferToReceiveVideo': self.getMediaVideo(),
                        IceRestart: iceRestart
                    }
                });
    };

    /*
     * Enabler implementation lies on webRtcPluginAdaptor.js
     * processEnablerHold to be used when the enabler plugin 30 is enabled.
     */
    self.processHold = function(call, hold, local_hold_status, successCallback, failureCallback) {
        logger.debug("processHold: local hold= " + local_hold_status + " remote hold= " + hold + " state= " + call.peer.signalingState);
        var peer = call.peer, updateSdp, audioDirection, videoDirection, answerSdp,
                successSdp, peerRemoteSdp, prevRemoteSdp, peerLocalSdp, localSdp, newPeerCreated = false;

        call.stableRemoteSdp = peer.remoteDescription.sdp;
        call.stableLocalSdp = peer.localDescription.sdp;

        if (!local_hold_status && !hold) {
            self.muteOnHold(call, false);
        }

        call.sdp = sdpParser.checkSupportedVideoCodecs(call.sdp, null);
        call.sdp = sdpParser.performVideoPortZeroWorkaround(call.sdp);
        call.sdp = sdpParser.checkAndRestoreICEParams(call.sdp, sdpParser.getSdpFromObject(call.peer.localDescription));
        call.sdp = sdpParser.removeG722Codec(call.sdp);
        call.sdp = sdpParser.performG722ParameterWorkaround(call.sdp);
        call.sdp = sdpParser.performVP8RTCPParameterWorkaround(call.sdp);
        call.sdp = sdpParser.fixRemoteTelephoneEventPayloadType(call, call.sdp);
        call.sdp = sdpParser.performVP8BandwidthWorkaround(call.sdp);

        call.sdp = sdpParser.setMediaActPass(call.sdp, self.isDtlsEnabled());

        // is this necessary?, if so below code should be revised,
        // as it is not changing directions in the sdp
//        if (!sdpParser.isSdpContainsAudioDirection(call.sdp) &&
//                !sdpParser.isSdpContainsVideoDirection(call.sdp)) {
//            if (hold || local_hold_status) {
//                logger.debug("processHold: call.sdp has no direction so setting as inactive for " + (hold ? "remote hold" : "remote unhold with local hold"));
//                call.sdp = sdpParser.updateAudioSdpDirectionToInactive(call.sdp);
//                call.sdp = sdpParser.updateVideoSdpDirectionToInactive(call.sdp);
//            } else {
//                logger.debug("processHold: call.sdp has no direction so setting as sendrecv for unhold");
//                call.sdp = sdpParser.updateAudioSdpDirection(call.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE);
//                call.sdp = sdpParser.updateVideoSdpDirection(call.sdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE);
//            }
//        }

        audioDirection = sdpParser.getAudioSdpDirection(call.sdp);
        videoDirection = sdpParser.getVideoSdpDirection(call.sdp);

        updateSdp = self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.OFFER, call.sdp);
        peerLocalSdp = sdpParser.getSdpFromObject(peer.localDescription);
        prevRemoteSdp = sdpParser.deleteSsrcFromSdp(call.prevRemoteSdp);
        peerRemoteSdp = self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.OFFER, sdpParser.getSdpFromObject(updateSdp));
        peerRemoteSdp.audioDirection = CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE;    //Chrome38 fix
        peerRemoteSdp.videoDirection = CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE;    //Chrome38 fix

        //call.sdp is given below because of plugin crash
        if (self.createNewPeerForCallIfIceChangedInRemoteSdp(call, call.sdp, call.prevRemoteSdp)) {
            peer = call.peer;
            newPeerCreated = true;
        }
        //peerRemoteSdp.sdp = sdpParser.deleteSsrcFromSdp(peerRemoteSdp.sdp);

                function processHoldSetFirstRemoteDescriptionSuccessCallback() {
                    updateSdp.audioDirection = CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE;
                    //updateSdp.videoDirection = videoDirection;

                    if (sdpParser.getVideoSdpDirection(updateSdp.sdp) === CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE ||
                        sdpParser.getVideoSdpDirection(updateSdp.sdp) === CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY)
                    {
                        updateSdp.sdp = sdpParser.deleteInactiveVideoSsrc(updateSdp.sdp);
                    }
                    peer.setRemoteDescription(
                            updateSdp,
                            function processHoldSetSecondRemoteDescriptionSuccessCallback() {
                                if (!hold && !local_hold_status && (videoDirection === CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE)) {
                                    call.remoteVideoState = CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY;
                                } else {
                                    call.remoteVideoState = updateSdp.videoDirection;
                                }
                                //check if remote party sends video
                                webRtcAdaptorUtils.callSetReceiveVideo(call);
                                peer.createAnswer(
                                        peer.remoteDescription,
                                        function processHoldCreateAnswerSuccessCallback(obj) {
                                            localSdp = sdpParser.getSdpFromObject(obj);
                                            logger.debug("processHold: isSdpEnabled audio= " + sdpParser.isAudioSdpEnabled(obj.sdp));
                                            logger.debug("processHold: isSdpEnabled video= " + sdpParser.isVideoSdpEnabled(obj.sdp));
                                            obj = null;

                                            if (hold) {
                                                logger.debug("processHold: Remote HOLD");

                                                localSdp = sdpParser.respondToRemoteSdpDirections(localSdp, call.sdp);

                                                // is this necessary?, if so below code should be revised,
                                                // as it is not changing directions in the sdp
//                                if ((sr_indx + 1) + (so_indx + 1) + (ro_indx + 1) + (in_indx + 1) === 0) {
//                                    logger.debug("processNativeHold: no direction detected so setting as inactive");
//                                    obj.sdp = updateSdpDirection(obj.sdp, audio, MEDIA_STATE.INACTIVE);
//                                    obj.sdp = updateSdpDirection(obj.sdp, video, MEDIA_STATE.INACTIVE);
//                                }
                                            } else if (!local_hold_status) {
                                                logger.debug("processHold: Remote UNHOLD: direction left as it is");

                                                if (webRtcAdaptorUtils.callCanLocalSendVideo(call)) {
                                                    if (sdpParser.isSdpVideoSendEnabled(call.sdp)) {
                                                        localSdp = sdpParser.updateVideoSdpDirection(localSdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE);
                                                    } else {
                                                        if (videoDirection === CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE) {
                                                            localSdp = sdpParser.updateVideoSdpDirection(localSdp, CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE);
                                                        }
                                                        else {
                                                            localSdp = sdpParser.updateVideoSdpDirection(localSdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_ONLY);
                                                        }
                                                    }
                                                } else {
                                                    if (sdpParser.isSdpVideoSendEnabled(call.sdp)) {
                                                        localSdp = sdpParser.updateVideoSdpDirection(localSdp, CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY);
                                                    } else {
                                                        localSdp = sdpParser.updateVideoSdpDirection(localSdp, CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE);
                                                    }
                                                }
                                                //change audio's direction to sendrecv for ssl attendees in a 3wc
                                                localSdp = sdpParser.changeDirection(localSdp, CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE, CONSTANTS.STRING.AUDIO);
                                            } else if (local_hold_status && !hold) {
                                                logger.debug("processHold: Remote UNHOLD on local hold");

                                                if (audioDirection === CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE) {
                                                    localSdp = sdpParser.updateAudioSdpDirectionToInactive(localSdp);
                                                } else {
                                                    localSdp = sdpParser.updateAudioSdpDirection(localSdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_ONLY);
                                                }

                                                if (webRtcAdaptorUtils.callCanLocalSendVideo(call)) {
                                                    localSdp = sdpParser.updateVideoSdpDirection(localSdp, CONSTANTS.WEBRTC.MEDIA_STATE.SEND_ONLY);
                                                } else {
                                                    localSdp = sdpParser.updateVideoSdpDirectionToInactive(localSdp);
                                                }
                                            }

                                            localSdp = sdpParser.performVP8RTCPParameterWorkaround(localSdp);
                                            localSdp = sdpParser.updateVersion(peerLocalSdp, localSdp);
                                            localSdp = sdpParser.checkIceParamsLengths(localSdp, updateSdp.sdp);
                                            localSdp = sdpParser.fixLocalTelephoneEventPayloadType(call, localSdp);

                                            // is this necessary? missing in native side.
                                            localSdp = sdpParser.setMediaPassive(localSdp, self.isDtlsEnabled());

                                            localSdp = sdpParser.updateH264Level(localSdp);

                                            if (newPeerCreated) {
                                                localSdp = sdpParser.copyCandidatesToTheNewLocalSdp(peerLocalSdp, localSdp);
                                                newPeerCreated = false;
                                                call.offer = self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.OFFER, peerLocalSdp);
                                            }
                                            answerSdp = self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.ANSWER, localSdp);
                                            call.answer = answerSdp;       // ABE-1328

                                            peer.setLocalDescription(
                                                    answerSdp,
                                                    function processHoldSetLocalDescriptionSuccessCallback() {
                                                        successSdp = sdpParser.getSdpFromObject(answerSdp);
                                                        if (sdpParser.isMediaPortReady(successSdp)) {
                                                            if (call.successCallback) {
                                                                utils.callFunctionIfExist(successCallback, successSdp);
                                                                call.successCallback = null;
                                                                call.offer = null;
                                                                call.answer = null;
                                                            }
                                                        }
                                                    },
                                                    function processHoldSetLocalDescriptionFailureCallback(e) {
                                                        logger.debug("processHold: setLocalDescription failed!! " + e);
                                                        utils.callFunctionIfExist(failureCallback, "Session cannot be created");
                                                        call.answer = null;       // ABE-1328
                                                    });
                                        },
                                        function processHoldCreateAnswerFailureCallback(e) {
                                            logger.debug("processHold: createAnswer failed!!: " + e);
                                            utils.callFunctionIfExist(failureCallback, "Session cannot be created");
                                        },
                                        {
                                            'mandatory': {
                                                'OfferToReceiveAudio': self.getMediaAudio(),
                                                'OfferToReceiveVideo': self.getMediaVideo()
                                            }
                                        });
                            },
                            function processHoldSetSecondRemoteDescriptionFailureCallback(e) {
                                logger.debug("processHold: second setRemoteDescription failed!! " + e);
                                utils.callFunctionIfExist(failureCallback, "Session cannot be created");
                            });
                }

                function processHoldSetFirstRemoteDescriptionFailureCallback(e) {
                    logger.debug("processHold: first setRemoteDescription failed!! " + e);
                    utils.callFunctionIfExist(failureCallback, "Session cannot be created");
                }

        // 1st setRemoteDescription to make webrtc remove the audio and/or video streams
        // 2nd setRemote will add the audio stream back so that services like MOH can work
        // This code will also run in UnHold scenario, and it will remove & add video stream
        if (newPeerCreated) {
            processHoldSetFirstRemoteDescriptionSuccessCallback();
        } else {
            peer.setRemoteDescription(
                peerRemoteSdp,
                processHoldSetFirstRemoteDescriptionSuccessCallback,
                processHoldSetFirstRemoteDescriptionFailureCallback
            );
        }
    };

    /*
     * Enabler implementation lies on webRtcPluginAdaptor.js
     * processHoldRespond to be used when the enabler plugin is enabled
     */
    self.processHoldRespond = function(call, onSuccess, onFailure, isJoin) {
        var remoteAudioDirection,
            remoteVideoDirection,
            localHoldFlag = false,
            remoteHoldFlag = false;

        logger.debug("processHoldRespond: state= " + call.peer.signalingState + " call.currentState= " + call.currentState);

        call.sdp = sdpParser.checkSupportedVideoCodecs(call.sdp, sdpParser.getSdpFromObject(call.peer.localDescription));
        call.sdp = sdpParser.removeRTXCodec(call.sdp);
        call.sdp = sdpParser.fixRemoteTelephoneEventPayloadType(call, call.sdp);
        call.sdp = sdpParser.removeG722Codec(call.sdp);
        call.sdp = sdpParser.performG722ParameterWorkaround(call.sdp);
        call.sdp = sdpParser.performVP8BandwidthWorkaround(call.sdp);

        sdpParser.init(call.sdp);
        remoteHoldFlag = sdpParser.isRemoteHold();

        localHoldFlag = (call.currentState === "LOCAL_HOLD");

        remoteAudioDirection = sdpParser.getAudioSdpDirection(call.sdp);
        remoteVideoDirection = sdpParser.getVideoSdpDirection(call.sdp);

        logger.debug("processHoldRespond: localHold= " + localHoldFlag + " remoteHold= " + remoteHoldFlag);

        /* Required for MOH - start */
        if (remoteHoldFlag === false) {
            if ((remoteAudioDirection === CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE) && (call.currentState === "REMOTE_HOLD")) {
                call.previousState = call.currentState;
                call.currentState = "COMPLETED";
            }
        } else {
            if (call.currentState === "COMPLETED") {
                call.previousState = call.currentState;
                call.currentState = "REMOTE_HOLD";
            }
        }

        if (localHoldFlag || remoteHoldFlag) {
            logger.debug("processHoldRespond: " + call.currentState + " : video -> inactive");
            call.sdp = sdpParser.updateSdpDirection(call.sdp, CONSTANTS.STRING.VIDEO, CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE);
        }

        if ((remoteVideoDirection === CONSTANTS.WEBRTC.MEDIA_STATE.INACTIVE) && (call.currentState === "COMPLETED")) {
            logger.debug("processHoldRespond: video inactive -> recvonly");
            call.sdp = sdpParser.updateSdpDirection(call.sdp, CONSTANTS.STRING.VIDEO, CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY);
        }
        /* Required for MOH - end */

        self.processRespond(call, onSuccess, onFailure, isJoin);
    };

    self.createUpdateWithSetLocalDescription = function(call, successCallback, failureCallback, isVideoStart, localSdp) {
        var peer = call.peer, localDesc, successSdp;
        logger.debug("set local description to start the video");

        if (!call.isVideoSourceAllowed) {
            self.replaceLocalStream(call);
        }
        if (self.getLocalVideoTrack(call.peer)) {
            self.getLocalVideoTrack(call.peer).enabled = isVideoStart;
        }

        localDesc = self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.OFFER, localSdp);
        if (isVideoStart) {
            localDesc.videoDirection = CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE;
        } else {
            localDesc.videoDirection = CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY;
        }

        peer.setLocalDescription(localDesc,
            function createUpdateSetLocalDescriptionSuccessCallback() {
                //since the candidates are same we can call the successCallback
                logger.debug("createUpdate: setLocalDescription success ");
                successSdp = sdpParser.updateH264Level(sdpParser.getSdpFromObject(localDesc));
                utils.callFunctionIfExist(successCallback, successSdp);
                call.successCallback = null;
            },
            function createUpdateSetLocalDescriptionFailureCallback(e) {
                logger.error("createUpdate: setLocalDescription failed : " + e);
                utils.callFunctionIfExist(failureCallback);
            });
    };

    self.createUpdateWithCreateOffer = function(call, successCallback, failureCallback, isVideoStart, localSdp, isIceLite) {
        var peer = call.peer, newSdp;
        logger.debug("create new offer to start the video: isIceLite = " + isIceLite);

        self.replaceLocalStream(call);
        self.setMediaVideo(sdpParser.isSdpHasVideo(localSdp));
        peer.createOffer(
            function createUpdateCreateOfferSuccessCallback(obj) {
                isVideoStart = isVideoStart && self.getVideoSourceAvailable();
                if (isVideoStart) {
                    obj.videoDirection = CONSTANTS.WEBRTC.MEDIA_STATE.SEND_RECEIVE;
                } else {
                    obj.videoDirection = CONSTANTS.WEBRTC.MEDIA_STATE.RECEIVE_ONLY;
                }

                newSdp = sdpParser.performVP8RTCPParameterWorkaround(sdpParser.getSdpFromObject(obj));
                obj = null;
                newSdp = sdpParser.updateH264Level(newSdp);
                newSdp = sdpParser.deleteCryptoZeroFromSdp(newSdp);
                newSdp = sdpParser.performVP8RTCPParameterWorkaround(newSdp);
                newSdp = sdpParser.updateAudioCodec(newSdp);
                newSdp = sdpParser.removeG722Codec(newSdp);
                newSdp = sdpParser.deleteCryptoFromSdp(newSdp, self.isDtlsEnabled());
                newSdp = sdpParser.setMediaActPass(newSdp, self.isDtlsEnabled());
                newSdp = sdpParser.fixLocalTelephoneEventPayloadType(call, newSdp);
                newSdp = sdpParser.replaceOpusCodec(newSdp);

                call.offer = self.getRtcLibrary().createRTCSessionDescription(CONSTANTS.WEBRTC.RTC_SDP_TYPE.OFFER, newSdp);

                peer.setLocalDescription(call.offer,
                    function createUpdateCreateOfferSetLocalDescriptionSuccessCallback() {
                        //since the candidates have changed we will call the successCallback at onEnablerIceCandidate
                        //utils.callFunctionIfExist(successCallback);
                        logger.debug("createUpdate: createOffer setLocalDescription success ");
                        webRtcAdaptorUtils.setLocalStreamVideoSendStatus(call, isVideoStart);
                    },
                    function crateUpdateCreateOfferSetLocalDescriptionFailureCallback(e) {
                        logger.debug("createUpdate: createOffer setLocalDescription failed: " + e);
                        utils.callFunctionIfExist(failureCallback);
                    });
            },
            function createUpdateCrateOfferFailureCallback(e) {
                logger.debug("createUpdate: createOffer failed!!: " + e);
                failureCallback();
            },
            {
                'mandatory': {
                    'OfferToReceiveAudio': self.getMediaAudio(),
                    'OfferToReceiveVideo': self.getMediaVideo(),
                    'IceRestart': !isIceLite
                }
            }
        );

    };

    // Enabler implementation lies on webRtcPluginAdaptor.js
    self.createPeer = function(call, onsuccess, onfailure) {
        try {
            var pc, constraints, i, servers = [], iceServerUrl = self.getIceServerUrl(), stunturn;
            if (iceServerUrl instanceof Array) {
                for (i = 0; i < iceServerUrl.length; i++) {
                    servers[i] = iceServerUrl[i];
                }
            } else if (iceServerUrl === null || iceServerUrl === "") {
                servers = [];
            } else {
                servers[0] = iceServerUrl;
            }
            stunturn = {iceServers: servers};

            constraints = {"optional": {"DtlsSrtpKeyAgreement": self.isDtlsEnabled()}};
            pc = self.getRtcLibrary().createRTCPeerConnection(stunturn, constraints);

            self.setPeerCount(self.getPeerCount() + 1);
            call.peer = pc;

            pc.onconnecting = function(event) {
                self.onSessionConnecting(call, event);
            };
            pc.onopen = function(event) {
                self.onSessionOpened(call, event);
            };
            pc.onsignalingstatechange = function(event) {
                self.onSignalingStateChange(call, event);
            };
            pc.onaddstream = function(event) {
                self.onRemoteStreamAdded(call, event);
            };
            pc.onremovestream = function(event) {
                self.onRemoteStreamRemoved(call, event);
            };
            pc.onicecandidate = function(event) {
                self.setupIceCandidateCollectionTimer(call);
                self.onIceCandidate(call, event);
            };
            pc.onicecomplete = function() {
                self.onIceComplete(call);
            };
            pc.oniceconnectionstatechange = function (event) {
                self.oniceconnectionstatechange(call, event);
            };

            logger.info("create PeerConnection successfully.");
            utils.callFunctionIfExist(onsuccess);
        } catch (err) {
            logger.error("Failed to create PeerConnection, exception: " + err.message);
            utils.callFunctionIfExist(onfailure);
        }
    };

    self.createNewPeerForCall = function(call) {
        var isNewPeerCreated = false, peerCount = self.getPeerCount();
        if (call.peer) {
            call.peer.close();
            self.setPeerCount(peerCount - 1);
        }

        logger.trace("Creating new peer for call: " + call.id);
        self.createPeer(call, function createPeerSuccessCallback() {
            logger.trace("New peer has created for call: " + call.id);
            call.peer.addStream(self.getLocalStream());
            isNewPeerCreated = true;
        }, function createPeerFailureCallback() {
            logger.error("New peer creation has failed!: " + call.id);
        });
        return isNewPeerCreated;
    };

    self.createNewPeerForCallIfIceChangedInRemoteSdp = function(call, newSdp, oldSdp) {
        var hasNewSdpContainsIceLite = sdpParser.isIceLite(newSdp),
                hasOldSdpContainsIceLite = sdpParser.isIceLite(oldSdp),
                isNewPeerCreated = false;

        // In Peer-Peer call, ice-iceLite change indicates
        // a new peer connection with different ip.
        // As for now, webrtc cannot handle ip change
        // without creating a peer.
        // For ex: Peer-Peer call and MoH.
        //
        // In Non Peer-Peer call, ice-iceLite change does
        // not occur so existing peer object will be used.

        if (hasNewSdpContainsIceLite !== hasOldSdpContainsIceLite) {
            logger.trace("Ice - Ice-Lite change detected in call: " + call.id);
            return self.createNewPeerForCall(call);
        }

        return isNewPeerCreated;
    };

    //Enabler implementation lies on webRtcPluginAdaptor.js
    self.onRemoteStreamAdded = function(call, event) {
        var streamUrl;
        logger.debug("onRemoteStreamAdded");
        if (event.stream) {
            streamUrl = self.getRtcLibrary().getURLFromStream(event.stream);
            if (streamUrl) {
                logger.debug("onRemoteStreamAdded: " + streamUrl);
                if (self.getDefaultVideoContainer()) {
                    self.useDefaultRenderer(streamUrl, false);
                } else if (self.getRemoteVideoContainer()) {
                    self.createStreamRenderer(streamUrl, self.getRemoteVideoContainer());
                } else {
                    self.fireOnStreamAddedEvent(call, streamUrl);
                }
            }
        }
    };

    self.iceCandidateCollectionTimeoutHandler = function(call) {
        var sdp = call.peer.localDescription.sdp;
        self.clearIceCandidateCollectionTimer(call);

        // set timeout if there is no ice candidate available or
        // when audio, video port assignment isn't complete
        if ((sdpParser.isSdpHasAudio(sdp) && sdpParser.isSdpHasAudioWithZeroPort(sdp)) ||
                (sdpParser.isSdpHasVideo(sdp) && sdpParser.isSdpHasVideoWithZeroPort(sdp))) {
            logger.debug("Re-setting ice candidate collection timeout: " + fcsConfig.iceCandidateCollectionTimeoutInterval);
            call.iceCandidateCollectionTimer = setTimeout(function() {
                self.iceCandidateCollectionTimeoutHandler(call);
            }, fcsConfig.iceCandidateCollectionTimeoutInterval);
            return;
        }

        if (call.successCallback) {
            logger.debug("Ice candidate collection interrupted after given timeout, invoking successCallback.");

            sdp = sdpParser.updateH264Level(sdp);

            call.successCallback(sdp);
            call.successCallback = null;
        }
    };

    self.setupIceCandidateCollectionTimer = function(call) {
        if (fcsConfig.iceCandidateCollectionTimeoutInterval) {
            if (!call.iceCandidateCollectionTimer) {
                logger.debug("Setting ice candidate collection timeout: " + fcsConfig.iceCandidateCollectionTimeoutInterval);
                call.iceCandidateCollectionTimer = setTimeout(function() {
                    self.iceCandidateCollectionTimeoutHandler(call);
                }, fcsConfig.iceCandidateCollectionTimeoutInterval);
            } else {
                logger.trace("Ice candidate collection timer exists.");
            }
        }
    };

    /*
     * Enabler implementation lies on webRtcPluginAdaptor.js
     * onIceCandidate to be called when the enabler plugin is enabled
     */
    self.onIceCandidate = function(call, event) {
        var sdp;
        if (event.candidate === null) {
            if (call.successCallback) {
                logger.debug("All ICE candidates received for call : " + call.id);

                sdp = sdpParser.getSdpFromObject(call.peer.localDescription);
                //sdp = sdp.replace("s=","s=genband");
                sdp = sdpParser.updateH264Level(sdp);

                call.successCallback(sdp);
                call.successCallback = null;
            }
        } else {
            call.iceCandidateReceived = true;
            logger.debug("ICE candidate received : sdpMLineIndex = " + event.candidate.sdpMLineIndex
                    + ", candidate = " + event.candidate.candidate + " for call : " + call.id);
        }
    };

    /*
     * Gets remote video resolutions with the order below
     * remoteVideoHeight-remoteVideoWidth
     *
     * Enabler implementation lies on webRtcPluginAdaptor.js
     */
    self.getRemoteVideoResolutions = function() {
        var remoteResolution = [],
            remoteVideoHeight,
            remoteVideoWidth;

        if (self.getRemoteVideoContainer()) {
            if (!self.getRemoteVideoContainer().firstChild) {
                return remoteResolution;
            }

            remoteVideoHeight = self.getRemoteVideoContainer().firstChild.videoHeight;
            remoteVideoWidth = self.getRemoteVideoContainer().firstChild.videoWidth;

        } else {
            if (!self.getDefaultVideoContainer().firstElementChild.firstChild) {
                return remoteResolution;
            }

            remoteVideoHeight = self.getDefaultVideoContainer().firstElementChild.firstChild.videoHeight;
            remoteVideoWidth = self.getDefaultVideoContainer().firstElementChild.firstChild.videoWidth;
        }

        logger.debug("remote video resolutions of plugin webrtc...");
        logger.debug("remoteVideoWidth  : " + remoteVideoWidth);
        logger.debug("remoteVideoHeight : " + remoteVideoHeight);

        remoteResolution.push(remoteVideoHeight);
        remoteResolution.push(remoteVideoWidth);

        self.getLocalVideoResolutions();

        return remoteResolution;
    };

    /*
     * Gets local video resolutions with the order below
     * localVideoHeight-localVideoWidth
     *
     * Enabler implementation lies on webRtcPluginAdaptor.js
     */
    self.getLocalVideoResolutions = function() {
        var localResolution = [],
            localVideoHeight,
            localVideoWidth;

        if (self.getLocalVideoContainer()) {
            if (!self.getLocalVideoContainer().firstChild) {
                return localResolution;
            }

            localVideoHeight = self.getLocalVideoContainer().firstChild.videoHeight;
            localVideoWidth = self.getLocalVideoContainer().firstChild.videoWidth;

        } else {
            if (!self.getDefaultVideoContainer().lastElementChild.firstChild) {
                return localResolution;
            }

            localVideoHeight = self.getDefaultVideoContainer().lastElementChild.firstChild.videoHeight;
            localVideoWidth = self.getDefaultVideoContainer().lastElementChild.firstChild.videoWidth;
        }

        logger.debug("local video resolutions of plugin webrtc...");
        logger.debug("localVideoWidth  : " + localVideoWidth);
        logger.debug("localVideoHeight : " + localVideoHeight);

        localResolution.push(localVideoHeight);
        localResolution.push(localVideoWidth);

        return localResolution;
    };

    // Enabler implementation lies on webRtcPluginAdaptor.js
    self.useDefaultRenderer = function(streamUrl, local) {
        var videoContainer;

        if (self.getDefaultVideoContainer() && self.getDefaultVideoContainer().children.length === 0) {
            //Create divs for the remote and local
            self.getDefaultVideoContainer().innerHTML = "<div style='height:100%;width:100%'></div><div style='position:absolute;bottom:10px;right:10px;height:30%; width:30%;'></div>";
        }

        if (local) {
            if (self.getLocalVideoContainer()) {
                videoContainer = self.getLocalVideoContainer();
            } else {
                videoContainer = self.getDefaultVideoContainer().lastElementChild;
            }
        } else {
            if (self.getRemoteVideoContainer()) {
                videoContainer = self.getRemoteVideoContainer();
            } else {
                videoContainer = self.getDefaultVideoContainer().firstElementChild;
            }
        }
        self.createStreamRenderer(streamUrl, videoContainer, {muted: local});
    };

    // Enabler implementation lies on webRtcPluginAdaptor.js
    self.createStreamRenderer = function(streamUrl, container, options) {
        var renderer;

        if (!streamUrl || !container) {
            return;
        }

        container.innerHTML = "<object width='100%' height='100%' type='application/x-gcfwenabler-video'><param name='autoplay' value='true' /><param name='videosrc' value='" + streamUrl + "' /></object>";

        return renderer;
    };

    //This function is called internally when we make a new call or hold/unhold scenario
    // Enabler implementation lies on webRtcPluginAdaptor.js
    self.addLocalStream = function(internalCall) {
        var streamUrl, fireEvent = false;
        logger.debug("addLocalStream");

        if (internalCall.localStream) {
            if (webRtcAdaptorUtils.callCanLocalSendVideo(internalCall)) {
                streamUrl = self.getRtcLibrary().getURLFromStream(internalCall.localStream);

                if (streamUrl) {
                    logger.debug("addLocalStream: " + streamUrl);
                    if (self.getDefaultVideoContainer()) {
                        self.useDefaultRenderer(streamUrl, true);
                    } else if (self.getLocalVideoContainer()) {
                        self.createStreamRenderer(streamUrl, self.getLocalVideoContainer(), {muted: true});
                    } else {
                        internalCall.call.localStreamURL = streamUrl;
                    }
                    fireEvent = true;
                }
            } else {
                if (self.getDefaultVideoContainer()) {
                    if (self.getDefaultVideoContainer().lastElementChild) {
                        self.disposeStreamRenderer(self.getDefaultVideoContainer().lastElementChild);
                        fireEvent = true;
                    }
                } else if (self.getLocalVideoContainer()) {
                    self.disposeStreamRenderer(self.getLocalVideoContainer());
                    fireEvent = true;
                }
            }

            if (fireEvent) {
                self.fireOnLocalStreamAddedEvent(internalCall);
            }
        }
    };

    // Enabler implementation lies on webRtcPluginAdaptor.js
    self.replaceLocalStream = function(internalCall) {
        logger.debug("replaceLocalStream");
        if (internalCall.peer.localStreams.length > 0) {
            internalCall.peer.removeStream(internalCall.peer.localStreams[0]);
        }
        internalCall.peer.addStream(self.getLocalStream());
        internalCall.localStream = self.getLocalStream();
    };

    // Enabler implementation lies on webRtcPluginAdaptor.js
    self.sendIntraFrame = function(call) {
        if (!call.peer) {
            return;
        }

        if (webRtcAdaptorUtils.callCanLocalSendVideo(call)) {
            call.peer.sendIntraFrame();
        } else {
            call.peer.sendBlackFrame();
        }
    };

    // Enabler implementation lies on webRtcPluginAdaptor.js
    self.sendBlackFrame = function(call) {
        if (!call.peer) {
            return;
        }
        call.peer.sendBlackFrame();
    };

    // Enabler implementation lies on webRtcPluginAdaptor.js
    self.performReconnectWorkaround = function(call, onSuccess, onFailure) {
        // this function is native only
        // it will do nothing for plugin side
        utils.callFunctionIfExist(onFailure);
    };

    logger.debug('WebRtcPluginAdaptor initialized');
};

var WebRtcPluginAdaptor = function(_super, _decorator, _model) {
    var decorator = _decorator || webRtcLibraryDecorator,
            model = _model || new WebRtcPluginAdaptorModel();
    return new WebRtcPluginAdaptorImpl(_super ||
            new WebRtcAdaptor({}, decorator, model),
            decorator,
            model,
            logManager);
};

if (__testonly__) {
    __testonly__.WebRtcPluginAdaptor = WebRtcPluginAdaptor;
}

var WebRtcPluginv21AdaptorImpl = function(_super, _decorator, _model, _logManager) {
    var self = this,
        webRtcPlugin21Version = {
            major: 2,
            minor: 1,

            min_revision: 343,
            min_build: 0,

            current_revision: 376,
            current_build: 0
        }, logger = _logManager.getLogger("WebRtcPluginv21AdaptorImpl");
    logger.debug('WebRtcPluginv21Adaptor initializing');

    utils.compose(_super, self);
    utils.compose(_model, self);

    self.setPluginVersion(webRtcPlugin21Version);
    logger.debug('WebRtcPluginv21Adaptor initialized');
};

var WebRtcPluginv21Adaptor = function(_super, _decorator, _model) {
    var decorator = _decorator || webRtcLibraryDecorator,
            model = _model || new WebRtcPluginAdaptorModel();
    return new WebRtcPluginv21AdaptorImpl(_super ||
            new WebRtcPluginAdaptor(undefined, decorator, model),
            decorator,
            model,
            logManager);
};

if (__testonly__) { __testonly__.WebRtcPluginv21Adaptor = WebRtcPluginv21Adaptor; }
var WebRtcPluginv22AdaptorImpl = function(_super, _decorator, _model, _logManager) {
    var self = this,
        webRtcPlugin22Version = {
            major: 2,
            minor: 2,

            min_revision: 477,
            min_build: 0,

            current_revision: 477,
            current_build: 0
        }, logger = _logManager.getLogger("WebRtcPluginv22AdaptorImpl");
    logger.debug('WebRtcPluginv22Adaptor initializing');

    utils.compose(_super, self);
    utils.compose(_model, self);

    self.setPluginVersion(webRtcPlugin22Version);
    logger.debug('WebRtcPluginv22Adaptor initialized');
};

var WebRtcPluginv22Adaptor = function(_super, _decorator, _model) {
    var decorator = _decorator || webRtcLibraryDecorator,
            model = _model || new WebRtcPluginAdaptorModel();
    return new WebRtcPluginv22AdaptorImpl(_super ||
            new WebRtcPluginAdaptor(undefined, decorator, model),
            decorator,
            model,
            logManager);
};

if (__testonly__) { __testonly__.WebRtcPluginv22Adaptor = WebRtcPluginv22Adaptor; }
var WebRtcPluginv30AdaptorImpl = function(_super, _decorator, _model, _logManager) {
    var self = this,
        webRtcPlugin30Version = {
            major: 3,
            minor: 0,

            min_revision: 476,
            min_build: 0,

            current_revision: 476,
            current_build: 0
        }, logger = _logManager.getLogger("WebRtcPluginv30AdaptorImpl");
    logger.debug('WebRtcPluginv30Adaptor initializing');

    utils.compose(_super, self);
    utils.compose(_model, self);

    self.setPluginVersion(webRtcPlugin30Version);
    logger.debug('WebRtcPluginv30Adaptor initialized');
};

var WebRtcPluginv30Adaptor = function(_super, _decorator, _model) {
    var decorator = _decorator || webRtcLibraryDecorator,
            model = _model || new WebRtcPluginAdaptorModel();
    return new WebRtcPluginv30AdaptorImpl(_super ||
            new WebRtcPluginAdaptor(undefined, decorator, model),
            decorator,
            model,
            logManager);
};

if (__testonly__) { __testonly__.WebRtcPluginv30Adaptor = WebRtcPluginv30Adaptor; }
var WebRtcChromeAdaptorImpl = function(_super, _decorator, _model, _logManager) {
    var self = this, logger = _logManager.getLogger("WebRtcChromeAdaptorImpl");
    logger.debug('WebRtcChromeAdaptor initializing');

    utils.compose(_super, self);
    logger.debug('WebRtcChromeAdaptor initialized');
};

var WebRtcChromeAdaptor = function(_super, _decorator, _model) {
    var decorator = _decorator || webRtcLibraryChromeDecorator,
            model = _model || new WebRtcChromeAdaptorModel();
    return new WebRtcChromeAdaptorImpl(_super ||
            new WebRtcAdaptor({}, decorator, model),
            decorator,
            model,
            logManager);
};

if (__testonly__) { __testonly__.WebRtcChromeAdaptor = WebRtcChromeAdaptor; }
var WebRtcFirefoxAdaptorImpl = function(_super, _decorator, _model, _logManager) {
    var self = this, logger = _logManager.getLogger("WebRtcFirefoxAdaptorImpl");
    logger.debug('WebRtcFirefoxAdaptor initializing');

    utils.compose(_super, self);
    logger.debug('WebRtcFirefoxAdaptor initialized');
};

var WebRtcFirefoxAdaptor = function(_super, _decorator, _model) {
    var decorator = _decorator || webRtcLibraryFirefoxDecorator,
            model = _model || new WebRtcFirefoxAdaptorModel();
    return new WebRtcFirefoxAdaptorImpl(_super ||
            new WebRtcAdaptor({}, decorator, model),
            decorator,
            model,
            logManager);
};

if (__testonly__) { __testonly__.WebRtcFirefoxAdaptor = WebRtcFirefoxAdaptor; }
var WebRtcAdaptorFactory = function(_window, _navigator, _logManager, _WebRtcPluginv21Adaptor, _WebRtcPluginv22Adaptor, _WebRtcPluginv30Adaptor, _WebRtcChromeAdaptor, _WebRtcFirefoxAdaptor) {
    var logger = _logManager.getLogger("WebRtcAdaptorFactory"),
    NAVIGATOR_TYPES = {CHROME: "chrome", FIREFOX: "firefox", "PLUGIN": "plugin"},
    PLUGIN_MODES = {
        WEBRTCH264: "webrtch264", // 3.0 Enabler Plugin
        WEBRTC22: "webrtc22", // 2.2 Enabler Plugin
        WEBRTC21: "webrtc21", // 2.1 Enabler Plugin
        WEBRTC: "webrtc", // Default Enabler Plugin
        AUTO: "auto", // Native For Chrome Browser and Default Enabler Plugin for other Browsers
        AUTO21: "auto21", // Native For Chrome Browser and Default Enabler Plugin for other Browsers
        AUTO22: "auto22", // Native For Chrome Browser and Default Enabler Plugin for other Browsers
        AUTOH264: "autoh264", // Native For Chrome Browser and 3.0 Enabler Plugin for other Browsers
        AUTOFIREFOX: "autofirefox" // Native For Chrome AND Firefox Browser and Enabler Plugin for other Browsers
     },
     DEFAULT_RTC_PLUGIN_MODE = PLUGIN_MODES.WEBRTC22,
     DEFAULT_RTC_ADAPTOR = _WebRtcPluginv22Adaptor,
     PLUGIN_MODE_LOOKUP_TABLE = {
        chrome: {webrtc: DEFAULT_RTC_PLUGIN_MODE,
                autofirefox: PLUGIN_MODES.AUTO,
                autoh264: PLUGIN_MODES.AUTO,
                webrtch264: PLUGIN_MODES.WEBRTCH264},
        firefox: {webrtc: DEFAULT_RTC_PLUGIN_MODE,
                auto: DEFAULT_RTC_PLUGIN_MODE,
                auto21: PLUGIN_MODES.WEBRTC21,
                auto22: PLUGIN_MODES.WEBRTC22,
                autoh264: PLUGIN_MODES.WEBRTCH264,
                autofirefox: PLUGIN_MODES.AUTO
                },
         plugin: {auto: DEFAULT_RTC_PLUGIN_MODE,
             auto21: PLUGIN_MODES.WEBRTC21,
             auto22: PLUGIN_MODES.WEBRTC22,
             autoh264: PLUGIN_MODES.WEBRTCH264,
             autofirefox: DEFAULT_RTC_PLUGIN_MODE,
             webrtc: DEFAULT_RTC_PLUGIN_MODE}},
    ADAPTOR_LOOKUP_TABLE = {
        chrome: {auto: _WebRtcChromeAdaptor,
            autoh264: _WebRtcChromeAdaptor,
            webrtc21: _WebRtcPluginv21Adaptor,
            webrtc22: _WebRtcPluginv22Adaptor,
            webrtch264: _WebRtcPluginv30Adaptor},
        firefox: {auto: _WebRtcFirefoxAdaptor,
            webrtc21: _WebRtcPluginv21Adaptor,
            webrtc22: _WebRtcPluginv22Adaptor,
            webrtch264: _WebRtcPluginv30Adaptor},
        plugin: {webrtc21: _WebRtcPluginv21Adaptor,
            webrtc22: _WebRtcPluginv22Adaptor,
            webrtch264: _WebRtcPluginv30Adaptor}
    }, pluginMode;

    function getNavigatorType() {
        if (_navigator.webkitGetUserMedia) {
            return NAVIGATOR_TYPES.CHROME;
        }
        else if (_navigator.mozGetUserMedia) {
            return NAVIGATOR_TYPES.FIREFOX;
        }
        else {
            return NAVIGATOR_TYPES.PLUGIN;
        }
    }


    function identifyPluginMode(options) {
        var i;

        if (!options || !options.pluginMode) {
            return PLUGIN_MODES.AUTO;
        }

        for(i in PLUGIN_MODES) {
            if (PLUGIN_MODES[i] === options.pluginMode) {
                return PLUGIN_MODES[i];
            }
        }

        return PLUGIN_MODES.AUTO;
    }

    function getPluginMode(options, navigatorType) {
        var pluginMode = identifyPluginMode(options);

        return PLUGIN_MODE_LOOKUP_TABLE[navigatorType][pluginMode] || pluginMode;
    }


    this.getWebRtcAdaptor = function(options) {
        var Adaptor, navigatorType = getNavigatorType();

        pluginMode = getPluginMode(options, navigatorType);

        Adaptor = ADAPTOR_LOOKUP_TABLE[navigatorType][pluginMode];

        if (!Adaptor) {
            // This seems unnecessary, still keeping it just in case of a weird
            // condition
            logger.debug("Invalid Plugin Mode Detected, Treated as WEBRTC");
            pluginMode = DEFAULT_RTC_PLUGIN_MODE;
            Adaptor = DEFAULT_RTC_ADAPTOR;
        }

        logger.debug("Adaptor initializing from " + navigatorType + " browser and " + pluginMode + " plugIn mode");
        _window.pluginMode = pluginMode;
        return new Adaptor();
    };

    this.getPluginModes = function() {
        return PLUGIN_MODES;
    };

    this.getDefaultRtcPluginMode = function() {
        return DEFAULT_RTC_PLUGIN_MODE;
    };

    this.getDefaultRtcAdaptor = function() {
        return DEFAULT_RTC_ADAPTOR;
    };
};

var webRtcAdaptorFactory = new WebRtcAdaptorFactory(window,
        navigator,
        logManager,
        WebRtcPluginv21Adaptor,
        WebRtcPluginv22Adaptor,
        WebRtcPluginv30Adaptor,
        WebRtcChromeAdaptor,
        WebRtcFirefoxAdaptor);
if (__testonly__) { __testonly__.WebRtcAdaptorFactory = WebRtcAdaptorFactory; }
var WebRtcManager = function(_webRtcAdaptorFactory, _logManager, _globalBroadcaster, _navigator) {
    var self = this, rtcAdaptor, turnCredentials,
            logger = _logManager.getLogger("WebRtcManager");

    function onTurnServerCredentialsAcquired(credentials) {
        turnCredentials = credentials;
    }

    /*
     * addTurnCredentialsToUrl to be used when there is an active Turn Server,
     * to replace it's credentials
     */
    function addTurnCredentialsToUrl(iceServerUrl) {
        var i, serverType;
        if (iceServerUrl instanceof Array) {
            for (i = 0; i < iceServerUrl.length; i++) {
                serverType = iceServerUrl[i].url.substring(0, iceServerUrl[i].url.indexOf(':'));
                if (serverType === 'turn' || serverType === 'turns') {
                    iceServerUrl[i].credential = turnCredentials.credential;
                    iceServerUrl[i].username = turnCredentials.username;
                }
            }
        }
        return iceServerUrl;
    }

    self.initMedia = function(onSuccess, onFailure, options) {
        var iceServerUrl = "";
        logger.info("Initializing media for call");
        rtcAdaptor = _webRtcAdaptorFactory.getWebRtcAdaptor(options);

        if (options) {
            if (options.iceserver) {
                iceServerUrl = options.iceserver;
                if (turnCredentials) {
                    iceServerUrl = addTurnCredentialsToUrl(iceServerUrl);
                }
                rtcAdaptor.setIceServerUrl(iceServerUrl);
            }
            if (options.webrtcdtls) {
                rtcAdaptor.setDtlsEnabled(options.webrtcdtls);
            }
        }

        rtcAdaptor.initMedia(onSuccess, onFailure, options);
    };

    self.getUserMedia = function(onSuccess, onFailure, options) {
        var videoResolutionArray;
        logger.info("getting user media for call: started - userAgent: " + _navigator.userAgent);

        if (options) {
            if (options.audio !== undefined) {
                rtcAdaptor.setMediaAudio(options.audio);
            }
            if (options.video !== undefined) {
                rtcAdaptor.setMediaVideo(options.video);
            }

            if (options.videoResolution) {
                // First element of array will be Width and second element will be Height
                videoResolutionArray = options.videoResolution.split("x");
                if (videoResolutionArray[0] && videoResolutionArray[1]) {
                    rtcAdaptor.setVideoWidth(videoResolutionArray[0]);
                    rtcAdaptor.setVideoHeight(videoResolutionArray[1]);
                }
            }
        }

        rtcAdaptor.getUserMedia(onSuccess, onFailure);
    };

    self.createOffer = function (call, successCallback, failureCallback, sendInitialVideo) {
        logger.info("create offer SDP: sendInitialVideo= " + sendInitialVideo);

        call.successCallback = successCallback;
        call.failureCallback = failureCallback;

        if (!call.peer) {
            rtcAdaptor.createPeer(call,
                function createPeerSuccessCallback() {},
                function createPeerFailureCallback() {
                    utils.callFunctionIfExist(failureCallback, 2);
                }
            );
        }
        rtcAdaptor.createOffer(call, successCallback, failureCallback, sendInitialVideo);
    };

    self.createAnswer = function(call, successCallback, failureCallback, isVideoEnabled) {
        logger.info("creating answer SDP: callid= " + call.id);
        logger.info("creating answer SDP: isVideoEnabled= " + isVideoEnabled);

        call.successCallback = successCallback;
        call.failureCallback = failureCallback;

        if (!call.peer) {
            rtcAdaptor.createPeer(call,
                    function createPeerSuccessCallback() {},
                    function createPeerFailureCallback() {
                        utils.callFunctionIfExist(failureCallback, 2);
                    }
            );
        }
        rtcAdaptor.createAnswer(call, successCallback, failureCallback, isVideoEnabled);
    };

    self.processAnswer = function(call, successCallback, failureCallback) {
        if (call.peer) {
            rtcAdaptor.processAnswer(call, successCallback, failureCallback);
        }
    };

    self.processRespond = function(call, onSuccess, onFailure, isJoin){
        if (call.peer) {
            rtcAdaptor.processRespond(call, onSuccess, onFailure, isJoin);
        }
    };

    self.createUpdate = function(call, successCallback, failureCallback, isVideoStart){
        logger.info("createUpdate: isVideoStart= " + isVideoStart);

        call.successCallback = successCallback;
        call.failureCallback = failureCallback;

        if(call.peer){
            rtcAdaptor.createUpdate(call, successCallback, failureCallback, isVideoStart);
        }
    };

    self.processUpdate = function(call, successCallback, failureCallback, local_hold_status) {
        logger.info("processUpdate: local_hold_status:" + local_hold_status);

        call.successCallback = successCallback;
        call.failureCallback = failureCallback;

        if (call.peer) {
            rtcAdaptor.processUpdate(call, successCallback, failureCallback, local_hold_status);
        }
    };

    self.createReOffer = function(call, successCallback, failureCallback, iceRestart) {
        call.successCallback = successCallback;
        call.failureCallback = failureCallback;

        if (call.peer) {
            rtcAdaptor.createReOffer(call, successCallback, failureCallback, iceRestart);
        }
    };

    self.createHoldUpdate = function(call, hold, remote_hold_status, successCallback, failureCallback){
        logger.info("create hold update local hold= " + hold + " remote hold= " + remote_hold_status);
        if(call.peer){
            rtcAdaptor.createHoldUpdate(call, hold, remote_hold_status, successCallback, failureCallback);
        }
    };

    self.processRemoteOfferOnLocalHold = function(call, successCallback, failureCallback) {
        if(call.peer){
            rtcAdaptor.processRemoteOfferOnLocalHold(call, successCallback, failureCallback);
        }
    };

    self.processEnd = function(call){
        if(call.peer){
            rtcAdaptor.processEnd(call);
        }
    };

    self.processHold = function(call, hold, local_hold_status, successCallback, failureCallback) {
        logger.info("processHold: local hold= " + local_hold_status + " remote hold= " + hold);

        if (call.peer) {
            call.successCallback = successCallback;
            rtcAdaptor.processHold(call, hold, local_hold_status, successCallback, failureCallback);
        }
    };

    self.processHoldRespond = function(call, onSuccess, onFailure, isJoin){
        logger.info("Processing response to hold offer sent");

        if(call.peer){
            rtcAdaptor.processHoldRespond(call, onSuccess, onFailure, isJoin);
        }
    };

    self.processPreAnswer = function(call){
        logger.info("processing preanswer from the offer we sent");

        if(call.peer){
            rtcAdaptor.processPreAnswer(call);
        }

    };

    self.revertRtcState = function(call, successCallback, failureCallback) {
        rtcAdaptor.revertRtcState(call, successCallback, failureCallback);
    };

    self.getRemoteVideoResolutions = function() {
        return rtcAdaptor.getRemoteVideoResolutions();
    };

    self.getLocalVideoResolutions = function() {
        return rtcAdaptor.getLocalVideoResolutions();
    };

    self.isAudioSourceAvailable = function() {
        return rtcAdaptor.getAudioSourceAvailable();
    };

    self.isVideoSourceAvailable = function() {
        return rtcAdaptor.getVideoSourceAvailable();
    };

    self.refreshVideoRenderer = function() {
        rtcAdaptor.refreshVideoRenderer();
    };

    self.performReconnectWorkaround = function(call, successCallback) {
        call.successCallback = successCallback;
        rtcAdaptor.performReconnectWorkaround(call);
    };

    self.sendIntraFrame = function(internalCall) {
        rtcAdaptor.sendIntraFrame(internalCall);
    };

    self.sendBlackFrame = function(internalCall) {
        rtcAdaptor.sendBlackFrame(internalCall);
    };

    self.getLocalAudioTrack = function(peer) {
        return rtcAdaptor.getLocalAudioTrack(peer);
    };

    self.addLocalStream = function(call) {
        rtcAdaptor.addLocalStream(call);
    };

    self.isPluginEnabled = function() {
        return rtcAdaptor.isPluginEnabled();
    };

    self.sendDTMF = function(call, tone){
        rtcAdaptor.sendDTMF(call, tone);
    };

    self.showSettingsWindow = function(){
        rtcAdaptor.getRtcLibrary().showSettingsWindow();
    };

    _globalBroadcaster.subscribe(CONSTANTS.EVENT.TURN_CREDENTIALS_ESTABLISHED, onTurnServerCredentialsAcquired);
    if (__testonly__) { self.setRtcLibrary = function(_rtcLibrary) { rtcAdaptor = _rtcLibrary; }; }
};

var webRtcManager = new WebRtcManager(webRtcAdaptorFactory, logManager, globalBroadcaster, navigator);
if (__testonly__) { __testonly__.WebRtcManager = WebRtcManager; }
var WebRtcAdaptorUtils = function (){

    var logger = logManager.getLogger("webRtcAdaptorUtils");

    /**
     * Sets call local stream video send status
     * Previous name of this method was "callSetLocalSendVideo" This message will be deleted.
     * @param {type} call
     * @param {type} status
     */
    this.setLocalStreamVideoSendStatus = function(call, status) {
        logger.debug("setLocalStreamVideoSendStatus= " + status);
        if (call.call) {
            call.call.setSendVideo(status);
        }
        call.peer.showLocalVideo = status;
    };

    // TODO: Optimize and refactor this method
    // setReceiveVideo = setReceiveRemoteVideo = setShowRemoteVideoContainer
    // setReceivingVideo = setSendLocalVideo = setShowLocalVideoContainer
    this.callSetReceiveVideo = function(call) {
        var status = sdpParser.getVideoSdpDirection(call.sdp);
        logger.debug("callSetReceiveVideo: status= " + status);
        call.call.setReceiveVideo(sdpParser.isSdpVideoSendEnabled(call.sdp));
        call.call.setReceivingVideo(sdpParser.isSdpVideoReceiveEnabled(call.sdp));
    };

    /**
     * Indicates call local stream video send status
     * @param {type} call
     * @returns true/false
     */
    this.callCanLocalSendVideo = function(call) {
        return call.call.canSendVideo();
    };
};

var webRtcAdaptorUtils = new WebRtcAdaptorUtils();
var Notification = function() {
    /**
     * Called on receipt of a 410 GONE message
     *
     * @name fcs.notification.onGoneReceived
     * @event
     *
     * @since 3.0.0
     *
     * @example
     * var goneReceived = function(data){
     *    // do something here
     * };
     *
     * fcs.notification.onGoneReceived = goneReceived;
     */

    /**
     * Manages a user's subscriptions to remote notifications.  A user may subscribe to specific
     * event types (calls, instant messages, presence updates) using SNMP or long polling.
     *
     * Note that call/im/presence event handlers must be assigned in other objects before calling
     * notificationSubscribe/extendNotificationSubscription.
     *
     * @name notification
     * @namespace
     * @memberOf fcs
     *
     * @version 3.0.4
     * @since 3.0.0
     *
     * @see fcs.config.notificationType
     * @see fcs.im.onReceived
     * @see fcs.call.onReceived
     * @see fcs.presence.onReceived
     *
     */

    /**
     * Enum for notification types.
     *
     * @name NotificationTypes
     * @property {string} LONGPOLLING Long polling type
     * @property {string} WEBSOCKET WebSocket type
     * @readonly
     * @memberOf fcs.notification
     */

    /**
     * Boolean for anonymous users.
     * Used by rest requests to determine some parameters at URL and body).
     *
     * @name isAnonymous
     * @return isAnonymous true if the user is anonymous
     * @since 3.0.0
     * @memberOf fcs.notification
     */

    /**
     * Unsubscribe from getting notifications
     *
     * @name fcs.notification.stop
     * @param {function} onSuccess Success callback
     * @param {function} onFailure Failure callback
     * @param {boolean} synchronous Determines if the operation is sync or async
     * @function
     * @since 3.0.0
     * @example
     * fcs.notification.stop(
     * //Success callback
     * function(){
     *     window.console.log("Notification system is stopped successfully!!")
     * },
     * //Failure callback
     * function(){
     *     window.console.log("Something Wrong Here!!!")
     * },
     * // synchronous
     * false
     * );
     */

    /**
     * Subscribe and fetch the notifications <BR />
     * NOTE: Before subscribing, you have to set handlers for received notification. Only handlers registered before starting the notification will receive events.
     * @name fcs.notification.start
     * @param {function} onSuccess Success callback
     * @param {function} onFailure Failure callback
     * @param {boolean} anonymous Is this an anonymous
     * @param {string} cachePrefix Prefix of the cache key to be used (this allows for multiple subscriptions)
     * @param {string} forceLogout Kills the session of the oldest device.(For more information : User Guide Demo Examples in Api Doc )
     * @function
     *
     * @since 3.0.0
     *
     * @example
     *
     * //Sets up connection and notification types
     * fcs.setup({
     *        "restUrl": "&lt;rest_url&gt;",
     *        "restPort": "rest_port",
     *        "websocketIP": "&lt;websocket_ip&gt;",
     *        "websocketPort": "&lt;websocket_port&gt;",
     *        "notificationType": "websocket",
     *        "callAuditTimer": "30000",
     *        "clientControlled" : true,
     *        "protocol" : "http",
     *        "serverProvidedTurnCredentials": "false"
     *});
     *
     * // Login
     * // User must login SPiDR to be able to receive and make calls
     * // Login includes authentication and subscription steps. After logging in you can receive notifications
     * // Provide username and password to the setUserAuth method
     * var incomingCall,outgoingCall;
     * fcs.setUserAuth("user@somedomain.com","password");
     * fcs.notification.start(function(){
     *       //Initialize media
     *       fcs.call.initMedia(function(){},function(){},{
     *                 "pluginLogLevel" : 2,
     *                 "videoContainer" : "",
     *                 "pluginMode" : "auto",
     *                 "iceserver" : [{"url":"stun:206.165.51.23:3478"}]
     *             });
     *       fcs.call.onReceived = function(call) {
     *       //Handle incoming notifications here (incomingCall, callEnd, etc.)
     *       //window.alert("incoming call");
     *       //call.onStateChange(state);
     *       //call.onStreamAdded(streamURL);
     *       incomingCall=call;
     *     }
     * },
     * function(){
     * window.console.log("Something Wrong Here!!!")
     * },
     * false,false,false
     * );
     *
     */

    /**
     * Sets the notification error handler.
     *
     * @name fcs.notification.setOnError
     * @param {function(error)} callback The failure callback to be called.
     * @function
     * @since 3.0.0
     */

    /**
     * Sets the notification success handler.
     *
     * @name fcs.notification.setOnSuccess
     * @param {function} callback The success callback to be called.
     * @function
     * @since 3.0.0
     */

    /**
     * Sets the connection lost handler.
     *
     * @name fcs.notification.setOnConnectionLost
     * @function
     * @since 3.0.0
     */

    /**
     * Sets the connection established handler.
     *
     * @name fcs.notification.setOnConnectionEstablished
     * @function
     * @since 3.0.0
     */

    /**
     * Will be used by external triggers to fetch notifications.
     *
     * @name fcs.notification.trigger
     * @function
     * @since 3.0.0
     * @example
     *
     * fcs.notification.start();
     *
     * //Native code received SNMP Trigger so retrieve the notification
     *
     * fcs.notification.trigger();
     *
     */
};

var NotificationCallBacks = {};
/*
 * Finite State machine that defines state transition of basic call model.
 * State machine fires events during state transitions.
 * Components should register to FSM  in order to receive transition events
 *
 */

var CallFSM = function(_logManager) {

    this.CallFSMState = {
        INIT: "INIT",
        RINGING: "RINGING",
        TRYING: "TRYING",
        ANSWERING : "ANSWERING",
        COMPLETED: "COMPLETED",
        RINGING_SLOW: "RINGING_SLOW",
        LOCAL_HOLD: "LOCAL_HOLD",
        LOCAL_HOLDING: "LOCAL_HOLDING",
        LOCAL_UNHOLDING: "LOCAL_UNHOLDING",
        LOCAL_VIDEO_STOP_START: "LOCAL_VIDEO_STOP_START",
        REMOTE_OFFER: "REMOTE_OFFER",
        REMOTE_HOLD: "REMOTE_HOLD",
        REMOTE_HOLDING: "REMOTE_HOLDING",
        REMOTE_UNHOLDING: "REMOTE_UNHOLDING",
        BOTH_HOLD: "BOTH_HOLD",
        JOINING: "JOINING",
        PROVISIONRECEIVED: "PROVISIONRECEIVED",
        REFER: "REFER",
        TRANSFERING: "TRANSFERING",
        LOCAL_SLOW_START_OFFER: "LOCAL_SLOW_START_OFFER",
        LOCAL_REOFFER: "LOCAL_REOFFER"
    };

    //CallFSM returns TransferEvent after state change
    this.TransferEvent = {
        unknownNotification_fsm: "unknownNotification_fsm",
        ignoredNotification_fsm: "ignoredNotification_fsm",
        callStart_fsm: "callStart_fsm",
        callReceived_fsm: "callReceived_fsm",
        answer_fsm: "answer_fsm",
        reject_GUI: "reject_GUI",
        callCompleted_fsm: "callCompleted_fsm",
        noAnswer_fsm: "noAnswer_fsm",
        localEnd_fsm: "localEnd_fsm",
        remoteEnd_fsm: "remoteEnd_fsm",
        answeringRingingSlow_fsm: "answeringRingingSlow_fsm",
        callCompletedAnswering_fsm: "callCompletedAnswering_fsm",
        localHold_fsm: "localHold_fsm",
        localHolding_fsm: "localHolding_fsm",
        remoteHold_fsm: "remoteHold_fsm",
        remoteHolding_fsm: "remoteHolding_fsm",
        localUnHold_fsm: "localUnHold_fsm",
        localUnHolding_fsm: "localUnHolding_fsm",
        remoteUnHold_fsm: "remoteUnHold_fsm",
        remoteUnHolding_fsm: "remoteUnHolding_fsm",
        localVideoStopStart_fsm: "localVideoStopStart_fsm",
        remoteOffer_fsm: "remoteOffer_fsm",
        joining_fsm: "joining_fsm",
        sessionComplete_fsm: "sessionComplete_fsm",
        joiningSuccess_fsm: "joiningSuccess_fsm",
        sessionFail_fsm: "sessionFail_fsm",
        ringing_fsm: "ringing_fsm",
        respondCallUpdate_fsm: "respondCallUpdate_fsm",
        remoteCallUpdate_fsm: "remoteCallUpdate_fsm",
        preCallResponse_fsm: "preCallResponse_fsm",
        forward_fsm: "forward_fsm",
        refer_fsm: "refer_fsm",
        accepted_fsm: "accepted_fsm",
        transfering_fsm: "transfering_fsm",
        transferSuccess_fsm: "transferSuccess_fsm",
        transferFail_fsm: "transferFail_fsm",
        respondCallHoldUpdate_fsm: "respondCallHoldUpdate_fsm",
        remoteOfferDuringLocalHold_fsm: "remoteOfferDuringHold_fsm",
        renegotiationCompleted_fsm: "renegotiationCompleted_fsm",
        slowStartOfferDuringRemoteHold_fsm : "slowStartOfferDuringRemoteHold_fsm",
        slowStartOfferDuringOnCall_fsm: "slowStartOfferDuringOnCall_fsm",
        stateReverted_fsm: "stateReverted_fsm",
        glareCondition_fsm: "glareCondition_fsm",
        sendReInvite_fsm: "sendReInvite_fsm",
        slowStartOfferProcessed_fsm : "slowStartOfferProcessed_fsm",
        performReconnectWorkaround_fsm: "performReconnectWorkaround_fsm"
    };

    //CallFSM receives NotificationEvent
    this.NotificationEvent = {
        callStart_GUI: "callStart_GUI",
        callNotify: "callNotify",
        ringing_Notify: "ringing_Notify",
        answer_GUI: "answer_GUI",
        end_GUI: "end_GUI",
        respondCallUpdate_Notify: "respondCallUpdate_Notify",
        respondCallUpdate_glareCondition_Notify: "respondCallUpdate_glareCondition_Notify",
        callCompleted_fsm: "callCompleted_fsm",
        callEnd_Notify: "callEnd_Notify",
        callNotify_noSDP: "callNotify_noSDP",
        startCallUpdate_slowStart_Notify: "startCallUpdate_slowStart_Notify",
        startCallUpdate_remoteHold_Notify: "startCallUpdate_remoteHold_Notify",
        startCallUpdate_remoteOffer_Notify: "startCallUpdate_remoteOffer_Notify",
        joining_Notify: "joining_Notify",
        sessionComplete_Notify: "sessionComplete_Notify",
        joiningSuccess_Notify: "joiningSuccess_Notify",
        sessionFail_Notify: "sessionFail_Notify",
        hold_GUI: "hold_GUI",
        unhold_GUI: "unhold_GUI",
        videoStopStart_GUI: "videoStopStart_GUI",
        sessionProgress: "sessionProgress",
        callCancel_Notify: "callCancel_Notify",
        forward_GUI: "forward_GUI",
        refer_JSL: "refer_JSL",
        accepted_Notify: "accepted_Notify",
        transfering: "transfering",
        requestFailure_JSL: "requestFailure_JSL",
        webrtcFailure_JSL: "webrtcFailure_JSL",
        remoteOfferProcessed_JSL: "remoteOfferProcessed_JSL",
        remoteHoldProcessed_JSL: "remoteHoldProcessed_JSL",
        remoteUnHoldProcessed_JSL: "remoteUnHoldProcessed_JSL",
        slowStartOfferProcessed_JSL: "slowStartOfferProcessed_JSL",
        performReconnectWorkaround_JSL: "performReconnectWorkaround_JSL",
        sendReInvite_JSL: "sendReInvite_JSL"
    };
    var self = this, logger = _logManager.getLogger("callFsm");

    function FSM (call, event, onSuccess, onFailure) {
        //TODO move sessionProgress somewhere else?
        var sessionProgress = "sessionProgress",
                callState = self.getCurrentState(call);
        switch (callState) {
            case self.CallFSMState.INIT:
                switch (event) {
                    case self.NotificationEvent.callStart_GUI:
                        call.currentState = self.CallFSMState.TRYING;
                        onSuccess(call, self.TransferEvent.callStart_fsm);
                        break;
                    case self.NotificationEvent.callNotify:
                        call.currentState = self.CallFSMState.RINGING;
                        onSuccess(call, self.TransferEvent.callReceived_fsm);
                        break;
                    case self.NotificationEvent.callNotify_noSDP:
                        call.currentState = self.CallFSMState.RINGING_SLOW;
                        onSuccess(call, self.TransferEvent.callReceived_fsm);
                        break;
                    case self.NotificationEvent.joiningSuccess_Notify:
                        call.currentState = self.CallFSMState.PROVISIONRECEIVED;
                        onSuccess(call, self.TransferEvent.joiningSuccess_fsm);
                        break;
                    default:
                        onFailure(call, self.TransferEvent.unknownNotification_fsm);
                        break;
                }
                break;
            case self.CallFSMState.RINGING:
                switch (event) {
                    case self.NotificationEvent.answer_GUI:
                        call.currentState = self.CallFSMState.COMPLETED;
                        onSuccess(call, self.TransferEvent.answer_fsm);
                        break;
                    case self.NotificationEvent.end_GUI:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.reject_GUI);
                        break;
                    case self.NotificationEvent.callNotify_noSDP:
                        call.currentState = self.CallFSMState.RINGING_SLOW;
                        onSuccess(call, self.TransferEvent.callReceived_fsm);
                        break;
                    case self.NotificationEvent.callEnd_Notify:
                    case self.NotificationEvent.callCancel_Notify:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.remoteEnd_fsm);
                        break;
                    case self.NotificationEvent.forward_GUI:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.forward_fsm);
                        break;
                    default:
                        onFailure(call, self.TransferEvent.unknownNotification_fsm);
                        break;
                }
                break;
            case self.CallFSMState.RINGING_SLOW:
                switch (event) {
                    case self.NotificationEvent.answer_GUI:
                        call.currentState = self.CallFSMState.ANSWERING;
                        onSuccess(call, self.TransferEvent.answerRingingSlow_fsm);
                        break;
                    case self.NotificationEvent.end_GUI:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.reject_GUI);
                        break;
                    case self.NotificationEvent.callEnd_Notify:
                    case self.NotificationEvent.callCancel_Notify:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.remoteEnd_fsm);
                        break;
                    case self.NotificationEvent.forward_GUI:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.forward_fsm);
                        break;
                    default:
                        onFailure(call, self.TransferEvent.unknownNotification_fsm);
                        break;
                }
                break;
            case self.CallFSMState.ANSWERING:
                switch (event) {
                    case self.NotificationEvent.respondCallUpdate_Notify:
                        call.currentState = self.CallFSMState.COMPLETED;
                        onSuccess(call, self.TransferEvent.callCompletedAnswering_fsm);
                        break;
                    case self.NotificationEvent.end_GUI:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.localEnd_fsm);
                        break;
                    case self.NotificationEvent.callEnd_Notify:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.remoteEnd_fsm);
                        break;
                    default:
                        onFailure(call, self.TransferEvent.unknownNotification_fsm);
                        break;
                }
                break;
            case self.CallFSMState.TRYING:
                switch (event) {
                    case self.NotificationEvent.sessionProgress:
                    case sessionProgress:
                        call.currentState = self.CallFSMState.PROVISIONRECEIVED;
                        onSuccess(call, self.TransferEvent.preCallResponse_fsm);
                        break;
                    case self.NotificationEvent.ringing_Notify:
                        call.currentState = self.CallFSMState.PROVISIONRECEIVED;
                        onSuccess(call, self.TransferEvent.ringing_fsm);
                        break;
                    case self.NotificationEvent.end_GUI:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.localEnd_fsm);
                        break;
                    case self.NotificationEvent.callEnd_Notify:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.noAnswer_fsm);
                        break;
                    case self.NotificationEvent.respondCallUpdate_Notify:
                        call.currentState = self.CallFSMState.COMPLETED;
                        onSuccess(call, self.TransferEvent.callCompleted_fsm);
                        break;
                    default:
                        onFailure(call, self.TransferEvent.unknownNotification_fsm);
                        break;
                }
                break;
            case self.CallFSMState.PROVISIONRECEIVED:
                switch (event) {
                    case self.NotificationEvent.respondCallUpdate_Notify:
                        call.currentState = self.CallFSMState.COMPLETED;
                        onSuccess(call, self.TransferEvent.callCompleted_fsm);
                        break;
                    case self.NotificationEvent.end_GUI:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.localEnd_fsm);
                        break;
                    case self.NotificationEvent.callEnd_Notify:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.remoteEnd_fsm);
                        break;
                    case self.NotificationEvent.ringing_Notify:
                        onSuccess(call, self.TransferEvent.ringing_fsm);
                        break;
                    case self.NotificationEvent.sessionProgress:
                    case sessionProgress:
                        onSuccess(call, self.TransferEvent.preCallResponse_fsm);
                        break;
                    default:
                        onFailure(call, self.TransferEvent.unknownNotification_fsm);
                        break;
                }
                break;
            case self.CallFSMState.COMPLETED:
                switch (event) {
                    case self.NotificationEvent.end_GUI:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.localEnd_fsm);
                        break;
                    case self.NotificationEvent.callEnd_Notify:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.remoteEnd_fsm);
                        break;
                    case self.NotificationEvent.startCallUpdate_remoteHold_Notify:
                        call.previousState = call.currentState;
                        call.currentState=self.CallFSMState.REMOTE_HOLDING;
                        onSuccess(call,self.TransferEvent.remoteHolding_fsm);
                        break;
                    case self.NotificationEvent.startCallUpdate_slowStart_Notify:
                        call.previousState = call.currentState;
                        call.currentState=self.CallFSMState.LOCAL_SLOW_START_OFFER;
                        onSuccess(call,self.TransferEvent.slowStartOfferDuringOnCall_fsm);
                        break;
                    case self.NotificationEvent.hold_GUI:
                        call.previousState = call.currentState;
                        call.currentState=self.CallFSMState.LOCAL_HOLDING;
                        onSuccess(call,self.TransferEvent.localHolding_fsm);
                        break;
                    case self.NotificationEvent.videoStopStart_GUI:
                        call.previousState = call.currentState;
                        call.currentState=self.CallFSMState.LOCAL_VIDEO_STOP_START;
                        onSuccess(call,self.TransferEvent.localVideoStopStart_fsm);
                        break;
                    case self.NotificationEvent.startCallUpdate_remoteOffer_Notify:
                        call.previousState = call.currentState;
                        call.currentState=self.CallFSMState.REMOTE_OFFER;
                        onSuccess(call,self.TransferEvent.remoteOffer_fsm);
                        break;
                    case self.NotificationEvent.transfering:
                        call.previousState = call.currentState;
                        call.currentState = self.CallFSMState.TRANSFERING;
                        onSuccess(call, self.TransferEvent.transfering_fsm);
                        break;
                    case self.NotificationEvent.callCancel_Notify:
                        onSuccess(call, self.TransferEvent.ignoredNotification_fsm);
                        break;
                    case self.NotificationEvent.performReconnectWorkaround_JSL:
                        call.previousState = call.currentState;
                        call.currentState=self.CallFSMState.LOCAL_REOFFER;
                        onSuccess(call,self.TransferEvent.performReconnectWorkaround_fsm);
                        break;
                    case self.NotificationEvent.sendReInvite_JSL:
                        call.previousState = call.currentState;
                        call.currentState=self.CallFSMState.LOCAL_REOFFER;
                        onSuccess(call,self.TransferEvent.sendReInvite_fsm);
                        break;
                    default:
                        onFailure(call, self.TransferEvent.unknownNotification_fsm);
                        break;
                }
                break;
            case self.CallFSMState.LOCAL_REOFFER:
                switch (event) {
                    case self.NotificationEvent.end_GUI:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.localEnd_fsm);
                        break;
                    case self.NotificationEvent.callEnd_Notify:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.remoteEnd_fsm);
                        break;
                    case self.NotificationEvent.respondCallUpdate_Notify:
                        call.currentState=call.previousState;
                        onSuccess(call,self.TransferEvent.respondCallUpdate_fsm);
                        break;
                    case self.NotificationEvent.webrtcFailure_JSL:
                    case self.NotificationEvent.requestFailure_JSL:
                        call.currentState=call.previousState;
                        onSuccess(call, self.TransferEvent.stateReverted_fsm);
                        break;
                    default:
                        onFailure(call, self.TransferEvent.unknownNotification_fsm);
                        break;
                }
                break;
            case self.CallFSMState.REMOTE_OFFER:
                switch (event) {
                    case self.NotificationEvent.end_GUI:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.localEnd_fsm);
                        break;
                    case self.NotificationEvent.callEnd_Notify:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.remoteEnd_fsm);
                        break;
                    case self.NotificationEvent.remoteOfferProcessed_JSL:
                        call.currentState=call.previousState;
                        onSuccess(call,self.TransferEvent.renegotiationCompleted_fsm);
                        break;
                    case self.NotificationEvent.requestFailure_JSL:
                    case self.NotificationEvent.webrtcFailure_JSL:
                        call.currentState=call.previousState;
                        onSuccess(call, self.TransferEvent.stateReverted_fsm);
                        break;
                    default:
                        onFailure(call, self.TransferEvent.unknownNotification_fsm);
                        break;
                }
                break;
            case self.CallFSMState.LOCAL_VIDEO_STOP_START:
                switch (event) {
                    case self.NotificationEvent.end_GUI:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.localEnd_fsm);
                        break;
                    case self.NotificationEvent.callEnd_Notify:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.remoteEnd_fsm);
                        break;
                    case self.NotificationEvent.respondCallUpdate_Notify:
                        call.currentState=call.previousState;
                        onSuccess(call,self.TransferEvent.respondCallUpdate_fsm);
                        break;
                    case self.NotificationEvent.requestFailure_JSL:
                    case self.NotificationEvent.webrtcFailure_JSL:
                        call.currentState=call.previousState;
                        onSuccess(call, self.TransferEvent.stateReverted_fsm);
                        break;
                    case self.NotificationEvent.respondCallUpdate_glareCondition_Notify:
                        call.currentState=call.previousState;
                        onSuccess(call, self.TransferEvent.glareCondition_fsm);
                       break;
                    default:
                        onFailure(call, self.TransferEvent.unknownNotification_fsm);
                        break;
                }
                break;
            case self.CallFSMState.LOCAL_HOLDING:
                switch (event) {
                    case self.NotificationEvent.end_GUI:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.localEnd_fsm);
                        break;
                    case self.NotificationEvent.callEnd_Notify:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.remoteEnd_fsm);
                        break;
                    case self.NotificationEvent.respondCallUpdate_Notify:
                        call.currentState = self.CallFSMState.LOCAL_HOLD;
                        if (call.previousState === self.CallFSMState.REMOTE_HOLD) {
                            call.currentState=self.CallFSMState.BOTH_HOLD;
                        }
                        call.previousState = callState;
                        onSuccess(call,self.TransferEvent.respondCallHoldUpdate_fsm);
                        break;
                    case self.NotificationEvent.requestFailure_JSL:
                    case self.NotificationEvent.webrtcFailure_JSL:
                        call.currentState=call.previousState;
                        onSuccess(call, self.TransferEvent.stateReverted_fsm);
                        break;
                    case self.NotificationEvent.respondCallUpdate_glareCondition_Notify:
                        call.currentState=call.previousState;
                        onSuccess(call, self.TransferEvent.glareCondition_fsm);
                       break;
                    default:
                        onFailure(call, self.TransferEvent.unknownNotification_fsm);
                        break;
                }
                break;
            case self.CallFSMState.LOCAL_UNHOLDING:
                switch (event) {
                    case self.NotificationEvent.end_GUI:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.localEnd_fsm);
                        break;
                    case self.NotificationEvent.callEnd_Notify:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.remoteEnd_fsm);
                        break;
                    case self.NotificationEvent.respondCallUpdate_Notify:
                        call.currentState = self.CallFSMState.COMPLETED;
                        if (call.previousState === self.CallFSMState.BOTH_HOLD) {
                            call.currentState=self.CallFSMState.REMOTE_HOLD;
                        }
                        call.previousState = callState;
                        onSuccess(call,self.TransferEvent.respondCallHoldUpdate_fsm);
                        break;
                    case self.NotificationEvent.requestFailure_JSL:
                    case self.NotificationEvent.webrtcFailure_JSL:
                        call.currentState=call.previousState;
                        onSuccess(call, self.TransferEvent.stateReverted_fsm);
                        break;
                    case self.NotificationEvent.respondCallUpdate_glareCondition_Notify:
                        call.currentState=call.previousState;
                        onSuccess(call, self.TransferEvent.glareCondition_fsm);
                       break;
                    default:
                        onFailure(call, self.TransferEvent.unknownNotification_fsm);
                        break;
                }
                break;
            case self.CallFSMState.LOCAL_HOLD:
                switch (event) {
                    case self.NotificationEvent.end_GUI:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.localEnd_fsm);
                        break;
                    case self.NotificationEvent.callEnd_Notify:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.remoteEnd_fsm);
                        break;
                    case self.NotificationEvent.startCallUpdate_remoteHold_Notify:
                        call.previousState = call.currentState;
                        call.currentState = self.CallFSMState.REMOTE_HOLDING;
                        onSuccess(call, self.TransferEvent.remoteHolding_fsm);
                        break;
                    case self.NotificationEvent.startCallUpdate_remoteOffer_Notify:
                        onSuccess(call, self.TransferEvent.remoteOfferDuringLocalHold_fsm);
                        break;
                    case self.NotificationEvent.unhold_GUI:
                        call.previousState = call.currentState;
                        call.currentState=self.CallFSMState.LOCAL_UNHOLDING;
                        onSuccess(call,self.TransferEvent.localUnHolding_fsm);
                        break;
                    case self.NotificationEvent.joining_Notify:
                        call.previousState = call.currentState;
                        call.currentState=self.CallFSMState.JOINING;
                        onSuccess(call,self.TransferEvent.joining_fsm);
                        break;
                    case self.NotificationEvent.transfering:
                        call.previousState = call.currentState;
                        call.currentState = self.CallFSMState.TRANSFERING;
                        onSuccess(call, self.TransferEvent.transfering_fsm);
                        break;
                    case self.NotificationEvent.performReconnectWorkaround_JSL:
                        call.previousState = call.currentState;
                        call.currentState=self.CallFSMState.LOCAL_REOFFER;
                        onSuccess(call,self.TransferEvent.performReconnectWorkaround_fsm);
                        break;
                    default:
                        onFailure(call, self.TransferEvent.unknownNotification_fsm);
                        break;
                }
                break;
            case self.CallFSMState.REMOTE_HOLDING:
                switch (event) {
                    case self.NotificationEvent.end_GUI:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.localEnd_fsm);
                        break;
                    case self.NotificationEvent.callEnd_Notify:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.remoteEnd_fsm);
                        break;
                    case self.NotificationEvent.remoteHoldProcessed_JSL:
                        call.currentState = self.CallFSMState.REMOTE_HOLD;
                        if (call.previousState === self.CallFSMState.LOCAL_HOLD) {
                            call.currentState=self.CallFSMState.BOTH_HOLD;
                        }
                        call.previousState = callState;
                        onSuccess(call,self.TransferEvent.remoteHold_fsm);
                        break;
                    case self.NotificationEvent.requestFailure_JSL:
                    case self.NotificationEvent.webrtcFailure_JSL:
                        call.currentState=call.previousState;
                        onSuccess(call, self.TransferEvent.stateReverted_fsm);
                        break;
                    default:
                        onFailure(call, self.TransferEvent.unknownNotification_fsm);
                        break;
                }
                break;
            case self.CallFSMState.REMOTE_UNHOLDING:
                switch (event) {
                    case self.NotificationEvent.end_GUI:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.localEnd_fsm);
                        break;
                    case self.NotificationEvent.callEnd_Notify:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.remoteEnd_fsm);
                        break;
                    case self.NotificationEvent.remoteUnHoldProcessed_JSL:
                        call.currentState = self.CallFSMState.COMPLETED;
                        if (call.previousState === self.CallFSMState.BOTH_HOLD) {
                            call.currentState=self.CallFSMState.LOCAL_HOLD;
                        }
                        call.previousState = callState;
                        onSuccess(call,self.TransferEvent.remoteUnHold_fsm);
                        break;
                    case self.NotificationEvent.requestFailure_JSL:
                    case self.NotificationEvent.webrtcFailure_JSL:
                        call.currentState=call.previousState;
                        onSuccess(call, self.TransferEvent.stateReverted_fsm);
                        break;
                    default:
                        onFailure(call, self.TransferEvent.unknownNotification_fsm);
                        break;
                }
                break;
            case self.CallFSMState.REMOTE_HOLD:
                switch (event) {
                    case self.NotificationEvent.end_GUI:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.localEnd_fsm);
                        break;
                    case self.NotificationEvent.callEnd_Notify:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.remoteEnd_fsm);
                        break;
                    case self.NotificationEvent.startCallUpdate_remoteHold_Notify:
                        call.previousState = call.currentState;
                        call.currentState = self.CallFSMState.REMOTE_HOLDING;
                        onSuccess(call, self.TransferEvent.remoteHolding_fsm);
                        break;
                    case self.NotificationEvent.startCallUpdate_remoteOffer_Notify:
                        call.previousState = call.currentState;
                        call.currentState = self.CallFSMState.REMOTE_UNHOLDING;
                        onSuccess(call, self.TransferEvent.remoteUnHolding_fsm);
                        break;
                    case self.NotificationEvent.startCallUpdate_slowStart_Notify:
                        call.previousState = call.currentState;
                        call.currentState=self.CallFSMState.LOCAL_SLOW_START_OFFER;
                        onSuccess(call,self.TransferEvent.slowStartOfferDuringRemoteHold_fsm);
                        break;
                    case self.NotificationEvent.hold_GUI:
                        call.previousState = call.currentState;
                        call.currentState=self.CallFSMState.LOCAL_HOLDING;
                        onSuccess(call,self.TransferEvent.localHolding_fsm);
                        break;
                    case self.NotificationEvent.joining_Notify:
                        call.previousState = call.currentState;
                        call.currentState=self.CallFSMState.JOINING;
                        onSuccess(call,self.TransferEvent.joining_fsm);
                        break;
                    case self.NotificationEvent.performReconnectWorkaround_JSL:
                        call.previousState = call.currentState;
                        call.currentState=self.CallFSMState.LOCAL_REOFFER;
                        onSuccess(call,self.TransferEvent.performReconnectWorkaround_fsm);
                        break;
                    default:
                        onFailure(call, self.TransferEvent.unknownNotification_fsm);
                        break;
                }
                break;
            case self.CallFSMState.BOTH_HOLD:
                switch (event) {
                    case self.NotificationEvent.end_GUI:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.localEnd_fsm);
                        break;
                    case self.NotificationEvent.callEnd_Notify:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.remoteEnd_fsm);
                        break;
                    case self.NotificationEvent.startCallUpdate_remoteHold_Notify:
                    case self.NotificationEvent.startCallUpdate_remoteOffer_Notify:
                        call.previousState = call.currentState;
                        call.currentState = self.CallFSMState.REMOTE_UNHOLDING;
                        onSuccess(call, self.TransferEvent.remoteUnHolding_fsm);
                        break;
                    case self.NotificationEvent.unhold_GUI:
                        call.previousState = call.currentState;
                        call.currentState=self.CallFSMState.LOCAL_UNHOLDING;
                        onSuccess(call,self.TransferEvent.localUnHolding_fsm);
                        break;
                    case self.NotificationEvent.joining_Notify:
                        call.previousState = call.currentState;
                        call.currentState=self.CallFSMState.JOINING;
                        onSuccess(call,self.TransferEvent.joining_fsm);
                        break;
                    case self.NotificationEvent.transfering:
                        call.previousState = call.currentState;
                        call.currentState = self.CallFSMState.TRANSFERING;
                        onSuccess(call, self.TransferEvent.transfering_fsm);
                        break;
                    case self.NotificationEvent.performReconnectWorkaround_JSL:
                        call.previousState = call.currentState;
                        call.currentState=self.CallFSMState.LOCAL_REOFFER;
                        onSuccess(call,self.TransferEvent.performReconnectWorkaround_fsm);
                        break;
                    default:
                        onFailure(call, self.TransferEvent.unknownNotification_fsm);
                        break;
                }
                break;
            case self.CallFSMState.LOCAL_SLOW_START_OFFER:
                switch (event) {
                    case self.NotificationEvent.end_GUI:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.localEnd_fsm);
                        break;
                    case self.NotificationEvent.callEnd_Notify:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.remoteEnd_fsm);
                        break;
                    case self.NotificationEvent.respondCallUpdate_Notify:
                        call.previousState = call.currentState;
                        call.currentState=self.CallFSMState.COMPLETED;
                        onSuccess(call,self.TransferEvent.respondCallUpdate_fsm);
                        break;
                    case self.NotificationEvent.requestFailure_JSL:
                    case self.NotificationEvent.webrtcFailure_JSL:
                        call.currentState=call.previousState;
                        onSuccess(call, self.TransferEvent.stateReverted_fsm);
                        break;
                    case self.NotificationEvent.slowStartOfferProcessed_JSL:
                        onSuccess(call, self.TransferEvent.slowStartOfferProcessed_fsm);
                    break;
                    default:
                        onFailure(call, self.TransferEvent.unknownNotification_fsm);
                        break;
                }
                break;
            case self.CallFSMState.JOINING:
                switch (event) {
                    case self.NotificationEvent.end_GUI:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.localEnd_fsm);
                        break;
                    case self.NotificationEvent.callEnd_Notify:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.remoteEnd_fsm);
                        break;
                    case self.NotificationEvent.sessionComplete_Notify:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.sessionComplete_fsm);
                        break;
                    case self.NotificationEvent.sessionFail_Notify:
                        call.currentState = call.previousState;
                        onSuccess(call, self.TransferEvent.sessionFail_fsm);
                        break;
                    case self.NotificationEvent.refer_JSL:
                        call.currentState = self.CallFSMState.REFER;
                        onSuccess(call, self.TransferEvent.refer_fsm);
                        break;
                    default:
                        onFailure(call, self.TransferEvent.unknownNotification_fsm);
                        break;
                }
                break;
            case self.CallFSMState.REFER:
                switch (event) {
                    case self.NotificationEvent.end_GUI:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.localEnd_fsm);
                        break;
                    case self.NotificationEvent.callEnd_Notify:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.remoteEnd_fsm);
                        break;
                    case self.NotificationEvent.sessionComplete_Notify:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.sessionComplete_fsm);
                        break;
                    case self.NotificationEvent.sessionFail_Notify:
                        call.currentState = call.previousState;
                        onSuccess(call, self.TransferEvent.sessionFail_fsm);
                        break;
                    //TODO Tolga - talk with lale
                    case self.NotificationEvent.accepted_Notify:
                        onSuccess(call, self.TransferEvent.accepted_fsm);
                        break;
                    default:
                        onFailure(call, self.TransferEvent.unknownNotification_fsm);
                        break;
                }
                break;
           case self.CallFSMState.TRANSFERING:
                switch (event) {
                    case self.NotificationEvent.end_GUI:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.localEnd_fsm);
                        break;
                    case self.NotificationEvent.callEnd_Notify:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.remoteEnd_fsm);
                        break;
                    case self.NotificationEvent.sessionComplete_Notify:
                        call.currentState = self.CallFSMState.INIT;
                        onSuccess(call, self.TransferEvent.transferSuccess_fsm);
                        break;
                    case self.NotificationEvent.sessionFail_Notify:
                        call.currentState = call.previousState;
                        onSuccess(call, self.TransferEvent.transferFail_fsm);
                        break;
                        //TODO this notification is consumed for now - it is there for completeness
                    case self.NotificationEvent.accepted_Notify:
                        onSuccess(call, self.TransferEvent.accepted_fsm);
                        break;
                    case self.NotificationEvent.startCallUpdate_slowStart_Notify:
                    case self.NotificationEvent.startCallUpdate_remoteHold_Notify:
                    case self.NotificationEvent.startCallUpdate_remoteOffer_Notify:
                        // Some client send hold during transfer
                        onSuccess(call, self.TransferEvent.remoteCallUpdate_fsm);
                        break;
                    default:
                        onFailure(call, self.TransferEvent.unknownNotification_fsm);
                        break;
                }
                break;
        }
    }

    self.getCurrentState = function(call){
        return (call.currentState ? call.currentState : self.CallFSMState.INIT);
    };

    this.handleEvent = function(call, event, handler) {
        var initialCallState;
        if (call) {
            initialCallState = self.getCurrentState(call);
            logger.info("FSM received NotificationEvent: " + event + " @ " +
                    initialCallState + " state" + ". Call Id: " + call.id);

            FSM(call, event,
                function(call, transferEvent) {
                    logger.debug("FSM handleEvent successful. (Call FSM) State Passed from " +
                            initialCallState + " to " +
                            self.getCurrentState(call) + ". TransferEvent: " +
                            transferEvent + ". Call Id: " + call.id);
                    handler(call, transferEvent);
                },
                function(call, transferEvent) {
                    logger.error("FSM handleEvent failure: " + transferEvent +
                            " @ " + self.getCurrentState(call) + ". Call Id: " +
                            call.id);
                    handler(call, transferEvent);
                });
        }
    };
};

var callFSM = new CallFSM(logManager);

if (__testonly__) { __testonly__.CallFSM = CallFSM; }

var CallControlService = function() {

    var logger = logManager.getLogger("callControlService");

    function addNotificationChannel(data){
        if(fcs.notification.isAnonymous() && window.cache.getItem("NotificationId")) {
            data.callMeRequest.notifyChannelId = window.cache.getItem("NotificationId");
        }
    }

    function errorParser(jqXHR){
        if (jqXHR && jqXHR.responseText) {
            return JSON.parse(jqXHR.responseText).callControlResponse;
        }
    }

    this.startCall = function(from, to, sdp, onSuccess, onFailure, convID) {

        logger.info("Call Start Function: " + from + " --> " + to);
        logger.info("Call Start Function: sdp : " + sdp);

        // response of the startCall contains callid/sessionData
        // callMe and callControl returns same response but object types have different namse
        function parseCallStart(data){
            var callid, response = fcs.notification.isAnonymous() ? data.callMeResponse:data.callControlResponse;
            if(response){
                callid = response.sessionData;
            }
            return callid;
        }

        function dataType() {
            var data;
            if (fcs.notification.isAnonymous()) {
                data = {
                    "callMeRequest":
                    {
                        "type":"callStart",
                        "from": from,
                        "to": to,
                        "sdp": sdp
                    }
                };
            }
            else {
                data = {
                    "callControlRequest":
                    {
                        "type":"callStart",
                        "from": from,
                        "to": to,
                        "sdp": sdp
                    }
                };
            }
            return data;
        }

        var data = dataType(), realm = getRealm();
        addNotificationChannel(data);

        if(convID) {
            data.callControlRequest.conversation = "convid="+convID;
        }

        server.sendPostRequest({
            "url": getWAMUrl(1, fcs.notification.isAnonymous() ? "/callme" + (realm?("?tokenrealm=" + realm):"") : "/callControl"),
            "data": data
        },
        onSuccess,
        onFailure,
        parseCallStart,
        errorParser
        );
    };

    this.audit = function(callid, onSuccess, onFailure){
        var data, realm = getRealm();

           if (fcs.notification.isAnonymous()) {
                data = {
                    "callMeRequest":
                    {
                        "type":"audit"
                    }
                };
            }
            else {
                data = {
                    "callControlRequest":
                    {
                        "type":"audit"
                    }
                };
            }
        //TODO JF verify if we need to always do that and not only for callme realm;
        if(realm){
          callid = callid.split("%0A")[0];
        }

        server.sendPutRequest({
            "url": getWAMUrl(1, (fcs.notification.isAnonymous() ? "/callme/callSessions/" : "/callControl/callSessions/") + callid + (realm?("?tokenrealm=" + realm):"")),
            "data": data
        }, onSuccess, onFailure, null, errorParser);
    };

    this.hold = function(callid , sdp , onSuccess , onFailure){
        logger.info("Hold Function : sdp : " + sdp);
        var data = {
            "callControlRequest":
            {
                "type":"startCallUpdate",
                "sdp": sdp
            }
        };

        server.sendPutRequest({
            "url": getWAMUrl(1, "/callControl/callSessions/" + callid),
            "data": data
        }, onSuccess, onFailure, null, errorParser);
    };

    this.unhold = function(callid , sdp , onSuccess , onFailure){
        logger.info("UnHold Function : sdp : " + sdp);
        var data = {
            "callControlRequest":
            {
                "type":"startCallUpdate",
                "sdp": sdp
            }
        };
        server.sendPutRequest({
            "url": getWAMUrl(1, "/callControl/callSessions/" + callid),
            "data": data
        }, onSuccess, onFailure, null, errorParser);
    };

    this.reinvite = function(callid , sdp , onSuccess , onFailure){
        logger.info("reinvite Function : sdp : " + sdp);

        var data = {
            "callControlRequest":
            {
                "type":"startCallUpdate",
                "sdp": sdp
            }
        };

        server.sendPutRequest({
            "url": getWAMUrl(1, "/callControl/callSessions/" + callid),
            "data": data
        }, onSuccess, onFailure, null, errorParser);
    };

    this.respondCallUpdate = function(callid , sdp , onSuccess , onFailure){
        logger.info("Respond Call Update Function : sdp : " + sdp);
        var data = {
            "callControlRequest":
            {
                "type":"respondCallUpdate",
                "sdp": sdp
            }
        };
        server.sendPutRequest({
            "url": getWAMUrl(1, "/callControl/callSessions/" + callid),
            "data": data
        }, onSuccess, onFailure, null, errorParser);
    };

    this.join = function (firstSessionData , secondSessionData , sdp , onSuccess , onFailure){
        logger.info("Join Function : sdp : " + sdp);
        function parseJoin(data){
            var callid, response = data.callControlResponse;

            if(response){
                callid = response.sessionData;
            }

            return callid;
        }

        var data = {
            "callControlRequest":
            {
                "type":"join",
                "firstSessionData":firstSessionData,
                "secondSessionData":secondSessionData,
                "sdp": sdp
            }
        };

        if(fcsConfig.clientControlled === "true") {
            data.callControlRequest.clientControlled = "true";
        }


        server.sendPostRequest({
            "url": getWAMUrl(1, "/callControl/"),
            "data": data
        },
        onSuccess,
        onFailure,
        parseJoin,
        errorParser
        );
    };

    this.refer = function(callid, referTo, referredBy, onSuccess , onFailure){
        logger.info("Refer Function : refer to: " + referTo);
        var data = {
            "callControlRequest":
            {
                "type": "refer",
                "from": referredBy,
                "to": referTo
            }
        };

        server.sendPutRequest({
            "url": getWAMUrl(1, "/callControl/callSessions/" + callid),
            "data": data
        }, onSuccess, onFailure, null, errorParser);
    };

    function makeCallControlRequest(type, callid , sdp, onSuccess, onFailure) {
        logger.info("makeCallControlRequest Function : sdp : " + sdp);
        var data = {
            "callControlRequest":{
                "type": type,
                "sdp": sdp
            }
        };

        server.sendPutRequest({
            "url": getWAMUrl(1, "/callControl/callSessions/" + callid),
            "data": data
        }, onSuccess, onFailure, null, errorParser);
    }

    function makeCallControlEndRequest(callid, onSuccess, onFailure) {
        var realm = getRealm();
        logger.info("makeCallControlEndRequest Function: " + callid);

        server.sendDeleteRequest({
            "url": getWAMUrl(1, fcs.notification.isAnonymous() ? "/callme/callSessions/" : "/callControl/callSessions/" + callid + (realm?("?tokenrealm=" + realm):"")),
            "data":{}
        },
        onSuccess,
        onFailure,
        null,
        errorParser
        );
    }

    this.endCall = function(callid, onSuccess, onFailure) {
        logger.info("endCall Function: " + callid);
        makeCallControlEndRequest(callid, onSuccess, onFailure, null, errorParser);
    };

    this.answerCall = function(callid, sdp, onSuccess, onFailure) {
        logger.info("Answer Call Function : sdp : " + sdp);
        makeCallControlRequest("callAnswer", callid, sdp, onSuccess, onFailure, null, errorParser);
    };

    function makeRequest(action, sessionData, onSuccess, onFailure, address) {
        logger.info("makeRequest Function with action : " + action);
        var data = {
            "callDispositionRequest":{
                "action": action,
                "sessionData": sessionData
            }
        };
        if(address){
            data.callDispositionRequest.address = address;
        }
        server.sendPostRequest({
            "url": getWAMUrl(1, "/calldisposition"),
            "data":data
        },
        onSuccess,
        onFailure,
        null,
        errorParser
        );
    }

    this.reject = function(callid, onSuccess, onFailure) {
        var dummy;
        logger.info("Reject Function: " + callid);
        makeRequest("reject", callid, onSuccess, onFailure, dummy, errorParser);
    };


    this.forward = function(callid, address , onSuccess, onFailure) {
        logger.info("Forward Function : address: " + address);
        makeRequest("forward", callid, onSuccess, onFailure, address);
    };

   this.transfer = function(callid , address , onSuccess , onFailure){
        logger.info("Call Transfer Function : target address: " + address);
        var data = {
            "callControlRequest":
            {
                "type":"transfer",
                "address": address
            }
        };

        server.sendPutRequest({
            "url": getWAMUrl(1, "/callControl/callSessions/" + callid),
            "data": data
        }, onSuccess, onFailure, null, errorParser);
    };
};

var callControlService = new CallControlService();

var CallManager = function(_webRtcManager, _callFSM, _callControlService,_sdpParser, _logManager) {

    /* AUDIT_KICKOFF_TIMEOUT is the interval we use to kickoff call audit after the call is setup.
     * The timeout is there to ensure we do not hit call setup race conditions when we try to kickoff the call audit */
    var calls = {}, logger = _logManager.getLogger("callManager"),
            AUDIT_KICKOFF_TIMEOUT = 3000, isReconnected = false,
            fsmNotificationEvent = _callFSM.NotificationEvent,
            fsmState = _callFSM.CallFSMState,
            self = this, isQueueEnabled = true,
            NOTIFICATION_STATE =
            {
                BUSY: 0,
                IDLE: 1
            }, CALL_STATES =
            {
                IN_CALL: 0,
                ON_HOLD: 1,
                RINGING: 2,
                ENDED: 3,
                REJECTED: 4,
                OUTGOING: 5,
                INCOMING: 6,
                ANSWERING: 7,
                JOINED: 8,
                RENEGOTIATION: 9,
                TRANSFERRED: 10,
                ON_REMOTE_HOLD: 11
            }, CALL_HOLD_STATES =
            {
                LOCAL_HOLD: 0,
                REMOTE_HOLD: 1,
                BOTH_HOLD: 2
            };

    function parseAddress(address, contact) {

        if (address.indexOf("sip:", 0) > -1) {
            address = address.replace("sip:", "");
        }
        var displayName = "";
        if (contact === undefined || contact === null) {
            return (address.indexOf("@", 0) > -1) ? "sip:" + address : address;
        }
        if (contact.firstName && contact.firstName !== "") {
            displayName += contact.firstName;
        }
        if (contact.lastName && contact.lastName !== "") {
            if (displayName === "") {
                displayName += contact.lastName;
            }
            else {
                displayName += " " + contact.lastName;
            }
        }
        if (displayName === "") {
            return (address.indexOf("@", 0) > -1) ? "sip:" + address : address;
        }
        return displayName + "<" + ((address.indexOf("@", 0) > -1) ? "sip:" + address : address) + ">";
    }

    /*
     * When connection re-establishes sets isReconnected flag true
     */
    function onConnectionLost() {
        isReconnected = true;
    }

    /*
     * clear call resources
     * clear long call audit
     * clear webrtc resources
     * triger web part
     *
     * @param call call object
     * @param state state that will be returned to web part
     */
    function clearResources(call) {
        if (call.call) {
            call.call.clearAuditTimer();
        }
        if (call.pendingRequestTimer) {
            clearTimeout(call.pendingRequestTimer);
        }
        //clear webRTC resources
        _webRtcManager.processEnd(call);
        //clear call object
        delete calls[call.id];
    }

    function setNotificationStateOfCallToBusy(internalCall) {
        logger.debug("Setting notification state to BUSY for call: " + internalCall.id);
        internalCall.notificationState = NOTIFICATION_STATE.BUSY;
    }

    function setNotificationStateOfCallToIdle(internalCall) {
        logger.debug("Setting notification state to IDLE for call: " + internalCall.id);
        internalCall.notificationState = NOTIFICATION_STATE.IDLE;
    }

    function isNotificationStateOfCallBusy(internalCall) {
        return internalCall.notificationState === NOTIFICATION_STATE.BUSY;
    }

    function triggerQueue(call) {
        if (!isQueueEnabled) {
            return;
        }
        logger.debug("NOTIFICATION_QUEUE: Process completed, notification queue state changed to IDLE");
        setNotificationStateOfCallToIdle(call);
        if (call.call.notificationQueue.size() > 0) {
            logger.debug("NOTIFICATION_QUEUE: New notification found in queue, processing it!");
            var notificationObj = call.call.notificationQueue.dequeue();
            self.onNotificationEvent(notificationObj.type, notificationObj.sessionParams);
        }
    }

    function onSubscriptionReEstablished() {
        var id, internalCall;
        if (isReconnected) {
            isReconnected = false;
            for (id in calls) {
                if (calls.hasOwnProperty(id)) {
                    internalCall = calls[id];
                    if (internalCall && _callFSM.getCurrentState(internalCall) !== fsmState.RINGING) {
                        setNotificationStateOfCallToBusy(internalCall);
                        self.delegateToCallFSM(internalCall, fsmNotificationEvent.performReconnectWorkaround_JSL);
                    }
                    else {
                        // If call signalingState is not stable, this call on ringing state. Call will be ended.
                        // Send 0 to delete the call
                        internalCall.call.onStateChange(CALL_STATES.ENDED, 0);
                        clearResources(internalCall);
                    }
                }
            }
        }
    }

    self.CALL_STATES = CALL_STATES;
    self.CALL_HOLD_STATES = CALL_HOLD_STATES;

    self.initMedia = function(onSuccess, onFailure, options) {
        _webRtcManager.initMedia(onSuccess, onFailure, options);
    };

    self.set_logSeverityLevel = function(level) {
        _webRtcManager.set_logSeverityLevel(level);
    };

    self.enable_logCallback = function() {
        _webRtcManager.enable_logCallback();
    };

    self.disable_logCallback = function() {
        _webRtcManager.disable_logCallback();
    };

    self.get_audioInDeviceCount = function() {
        _webRtcManager.get_audioInDeviceCount();
    };

    self.get_audioOutDeviceCount = function() {
        _webRtcManager.get_audioOutDeviceCount();
    };

    self.get_videoDeviceCount = function() {
        _webRtcManager.get_videoDeviceCount();
    };

    self.getUserMedia = function(onSuccess, onFailure, options) {
        _webRtcManager.getUserMedia(onSuccess, onFailure, options);
    };

    self.showSettingsWindow = function(onSuccess, onFailure, options) {
        _webRtcManager.showSettingsWindow(onSuccess, onFailure, options);
    };

    self.getVideoResolutions = function() {
        _webRtcManager.getVideoResolutions();
    };

    self.createStreamRenderer = function(streamId, container, options) {
        return _webRtcManager.createStreamRenderer(streamId, container, options);
    };

    self.disposeStreamRenderer = function(container) {
        _webRtcManager.disposeStreamRenderer(container);
    };

    self.isPluginEnabled = function() {
        return _webRtcManager.isPluginEnabled();
    };

    self.hasGotCalls = function() {
        var callid, internalCall;
        for (callid in calls) {
            if (calls.hasOwnProperty(callid)) {
                internalCall = calls[callid];
                if (internalCall) {
                    logger.info("has got call - id: " + callid + " - state: " + _callFSM.getCurrentState(internalCall));
                    return true;
                }
            }
        }
        return false;
    };

    self.getCalls = function() {
        return calls;
    };

    self.sendIntraFrame = function(callid) {
        var internalCall = calls[callid];
        if (internalCall) {
            _webRtcManager.sendIntraFrame(internalCall);
        }
    };

    self.sendBlackFrame = function(callid) {
        var internalCall = calls[callid];
        if (internalCall) {
            _webRtcManager.sendBlackFrame(internalCall);
        }
    };

    self.delegateToCallFSM = function(call, stateMessage) {
        _callFSM.handleEvent(call, stateMessage, self.onStateChange);
    };

    self.answer = function(callid, onSuccess, onFailure, isVideoEnabled, videoQuality) {
        var internalCall = calls[callid],
                videoNegotationAvailable = self.isVideoNegotationAvailable(callid);

        if (internalCall) {
            // check if term side tries to answer an audio only call with video
            if (videoNegotationAvailable === false && isVideoEnabled === true) {
                logger.error("[callManager.answer] Video Session Not Available Error ");
                utils.callFunctionIfExist(onFailure, fcs.Errors.VIDEO_SESSION_NOT_AVAILABLE);
                return;
            }

            internalCall.onIceStateFailure = function(sdp) {
                self.onIceStateFailure(internalCall, sdp);
            };

            if (internalCall.sdp) {
                //check with the state machine if the current state would accept an answer.
                if (_callFSM.getCurrentState(internalCall) !== fsmState.RINGING) {
                    utils.callFunctionIfExist(onFailure, fcs.Errors.STATE);
                }
                else {
                    self.getUserMedia(function(mediaInfo) {
                        internalCall.isVideoSourceAllowed = mediaInfo.video;
                        _webRtcManager.createAnswer(
                                internalCall,
                                function(sdp) {
                                    logger.info("[callManager.answer : sdp ]" + sdp);
                                    //change call state
                                    self.delegateToCallFSM(internalCall, fsmNotificationEvent.answer_GUI);
                                    //send answer call
                                    _callControlService.answerCall(
                                            internalCall.id,
                                            sdp,
                                            function() {
                                                //TODO: is this necessary
                                                _webRtcManager.addLocalStream(internalCall);
                                                utils.callFunctionIfExist(onSuccess);
                                            },
                                            onFailure);
                                },
                                function(errStr) {
                                    logger.error("[callManager.answer] Error : " + errStr);
                                    //Change state when the call have failed
                                    //This will trigger send reject
                                    self.delegateToCallFSM(internalCall, fsmNotificationEvent.end_GUI);
                                },
                                isVideoEnabled);
                    }, function(e) {
                        utils.callFunctionIfExist(onFailure, e);
                    },
                            {
                                "audio": true,
                                "video": videoNegotationAvailable ? true : false,
                                "audioIndex": 0,
                                "videoIndex": videoNegotationAvailable ? 0 : -1,
                                "videoResolution": videoQuality
                            });
                }
            }
            else {
                if (_callFSM.getCurrentState(internalCall) !== fsmState.RINGING_SLOW) {
                    utils.callFunctionIfExist(onFailure, fcs.Errors.STATE);
                }
                else {
                    self.getUserMedia(function(mediaInfo) {
                        internalCall.isVideoSourceAllowed = mediaInfo.video;
                        _webRtcManager.createOffer(internalCall, function(sdp) {
                            internalCall.sdp = sdp;
                            self.delegateToCallFSM(internalCall, fsmNotificationEvent.answer_GUI);
                            _callControlService.answerCall(internalCall.id, sdp, onSuccess, onFailure);
                        }, function() {
                            self.delegateToCallFSM(internalCall, fsmNotificationEvent.end_GUI);
                        },
                                isVideoEnabled);
                    }, function(e) {
                        utils.callFunctionIfExist(onFailure, e);
                    },
                            {
                                "audio": true,
                                "video": videoNegotationAvailable ? true : false,
                                "audioIndex": 0,
                                "videoIndex": videoNegotationAvailable ? 0 : -1,
                                "videoResolution": videoQuality
                            });

                }
            }
        }
    };

    self.getIncomingCallById = function(callid) {
        var call = null, cachedCall, internalCall;

        cachedCall = JSON.parse(cache.getItem(callid));
        if (cachedCall) {

            call = new fcs.call.IncomingCall(callid, {reject: cachedCall.optionReject, forward: cachedCall.optionForward, answer: cachedCall.optionAnswer});

            call.setReceiveVideo(_sdpParser.isSdpHasVideo(cachedCall.sdp));

            call.remoteConversationId = cachedCall.remoteConversationId;

            call.callerNumber = cachedCall.callerNumber;
            call.callerName = cachedCall.callerName;
            call.calleeNumber = cachedCall.calleeNumber;
            call.primaryContact = cachedCall.primaryContact;

            internalCall = {
                "call": call,
                "sdp": cachedCall.sdp,
                "id": callid
            };

            internalCall.onIceStateFailure = function(sdp) {
                self.onIceStateFailure(internalCall, sdp);
            };

            calls[callid] = internalCall;

            self.delegateToCallFSM(internalCall, fsmNotificationEvent.callNotify);
        }

        return call;
    };

    function cacheCall(internalCall) {
        var callToCache = {
            "sdp": internalCall.sdp,
            "remoteConversationId": internalCall.call.remoteConversationId,
            "callerNumber": internalCall.call.callerNumber,
            "callerName": internalCall.call.callerName,
            "calleeNumber": internalCall.call.calleeNumber,
            "primaryContact": internalCall.call.primaryContact,
            "optionReject": internalCall.call.canReject(),
            "optionForward": internalCall.call.canForward(),
            "optionAnswer": internalCall.call.canAnswer()
        };

        cache.setItem(internalCall.id, JSON.stringify(callToCache));
    }

    self.start = function(from, contact, to, onSuccess, onFailure, isVideoEnabled, sendInitialVideo, videoQuality, convID) {
        var internalCall = {};

        logger.info("start call... from: " + from
                + " contact: " + JSON.stringify(contact)
                + " to: " + to
                + " isVideoEnabled: " + isVideoEnabled
                + " sendInitialVideo: " + sendInitialVideo
                + " videoQuality: " + videoQuality
                + " convID: " + convID);

        self.getUserMedia(function(mediaInfo) {
            internalCall.isVideoSourceAllowed = mediaInfo.video;
            _webRtcManager.createOffer(internalCall,
                    function(sdp) {
                        logger.info("[callManager.start : sdp ]" + sdp);

                        internalCall.sdp = sdp;
                        _callControlService.startCall(
                                parseAddress(from, contact),
                                parseAddress(to),
                                sdp,
                                function(callid) {

                                    internalCall.call = new fcs.call.OutgoingCall(callid);
                                    internalCall.id = callid;

                                    internalCall.onIceStateFailure = function(sdp) {
                                        self.onIceStateFailure(internalCall, sdp);
                                    };

                                    self.delegateToCallFSM(internalCall, fsmNotificationEvent.callStart_GUI);
                                    calls[callid] = internalCall;
                                    internalCall.call.setSendVideo(sendInitialVideo);
                                    //TODO: is this necessary
                                    _webRtcManager.addLocalStream(internalCall);
                                    utils.callFunctionIfExist(onSuccess, internalCall.call);
                                },
                                function(e) {
                                    //TODO: update call state
                                    utils.callFunctionIfExist(onFailure, e);
                                },
                                convID
                                );
                    }, function(e) {
                logger.error("doOffer failed: " + e);
                utils.callFunctionIfExist(onFailure, e);
            },
                    sendInitialVideo
                    );
        }, function() {
            utils.callFunctionIfExist(onFailure);
        },
                {
                    "audio": true,
                    "video": isVideoEnabled ? true : false,
                    "audioIndex": 0,
                    "videoIndex": isVideoEnabled ? 0 : -1,
                    "videoResolution": videoQuality
                }
        );

    };
    self.reject = function(callid, onSuccess, onFailure) {
        var internalCall = calls[callid];
        if (!internalCall) {
            utils.callFunctionIfExist(onFailure, fcs.Errors.STATE);
            return;
        }

        _callControlService.reject(callid, function() {
            self.delegateToCallFSM(internalCall, fsmNotificationEvent.end_GUI);
            utils.callFunctionIfExist(onSuccess);
        },
                function() {
                    utils.callFunctionIfExist(onFailure);
                });

    };

    self.ignore = function(callid, onSuccess, onFailure) {
        var internalCall = calls[callid];
        if (!internalCall) {
            utils.callFunctionIfExist(onFailure, fcs.Errors.STATE);
            return;
        }

        self.delegateToCallFSM(internalCall, fsmNotificationEvent.end_GUI);
        utils.callFunctionIfExist(onSuccess);
    };
    self.forward = function(callid, address, onSuccess, onFailure) {
        var internalCall = calls[callid];
        if (!internalCall) {
            utils.callFunctionIfExist(onFailure, fcs.Errors.STATE);
            return;
        }

        _callControlService.forward(callid, address, function() {
            self.delegateToCallFSM(internalCall, fsmNotificationEvent.forward_GUI);
            utils.callFunctionIfExist(onSuccess);
        },
                function() {
                    utils.callFunctionIfExist(onFailure);
                });
    };

    function handleFailure(internalCall, failureHandler, failureEvent, retry) {
        setNotificationStateOfCallToBusy(internalCall);
        _webRtcManager.revertRtcState(internalCall, triggerQueue, triggerQueue);

        if (failureEvent) {
            self.delegateToCallFSM(internalCall, failureEvent);
        }

        if (retry && retry.timeout) {
            internalCall.pendingRequestTimer = setTimeout(function() {
                internalCall.pendingRequestTimer = null;
                retry.args.push(true);
                retry.handler.apply(null, retry.args);
            }, retry.timeout * 1000);
        }
        else {
            if (failureHandler) {
                utils.callFunctionIfExist(failureHandler);
            }
        }
    }

    function handleRequestFailure(internalCall, failureHandler, retry) {
        handleFailure(internalCall, failureHandler,
                fsmNotificationEvent.requestFailure_JSL, retry);
    }

    function handleWebrtcFailure(internalCall, failureHandler) {
        handleFailure(internalCall, failureHandler,
                fsmNotificationEvent.webrtcFailure_JSL);
    }

    self.hold = function(callid, onSuccess, onFailure, isAutoRetried) {
        var internalCall = calls[callid], currentCallState;
        if (!internalCall) {
            utils.callFunctionIfExist(onFailure, fcs.Errors.STATE);
            return;
        }

        if (isNotificationStateOfCallBusy(internalCall)){
            if (isAutoRetried) {
                utils.callFunctionIfExist(onFailure, fcs.Errors.NETWORK);
            }
            else {
                utils.callFunctionIfExist(onFailure, fcs.Errors.STATE);
            }
            return;
        }

        currentCallState = _callFSM.getCurrentState(internalCall);

        if (currentCallState !== fsmState.COMPLETED &&
                currentCallState !== fsmState.REMOTE_HOLD) {
            if (isAutoRetried) {
                utils.callFunctionIfExist(onFailure, fcs.Errors.NETWORK);
            }
            else {
                utils.callFunctionIfExist(onFailure, fcs.Errors.STATE);
            }
            return;
        }

        if (internalCall.pendingRequestTimer) {
            utils.callFunctionIfExist(onFailure, fcs.Errors.PENDING_REQUEST);
            return;
        }

        internalCall.lastUpdateRequest = {handler: self.hold,
            args: [callid, onSuccess, onFailure]};

        setNotificationStateOfCallToBusy(internalCall);

        self.delegateToCallFSM(internalCall, fsmNotificationEvent.hold_GUI);
        _webRtcManager.createHoldUpdate(internalCall,
                true,
                (currentCallState === fsmState.REMOTE_HOLD),
                function(sdp) {
                    logger.debug("[callManager.hold->createHoldUpdate : sdp ]" + sdp);
                    _callControlService.hold(internalCall.id, sdp,
                            function() {
                                setNotificationStateOfCallToIdle(internalCall);
                                internalCall.call.setHold(true);
                                internalCall.call.setHoldState(currentCallState);
                                utils.callFunctionIfExist(onSuccess);
                            },
                            function(err) {
                                handleRequestFailure(internalCall, onFailure,
                                        {handler: self.hold,
                                            args: [callid, onSuccess, onFailure],
                                            timeout: err.retryAfter});
                            });
                },
                function() {
                    handleWebrtcFailure(internalCall, onFailure);
                });

    };

    self.unhold = function(callid, onSuccess, onFailure, isAutoRetried) {
        var internalCall = calls[callid], currentCallState;

        if (!internalCall) {
            utils.callFunctionIfExist(onFailure, fcs.Errors.STATE);
            return;
        }

        if (isNotificationStateOfCallBusy(internalCall)){
            if (isAutoRetried) {
                utils.callFunctionIfExist(onFailure, fcs.Errors.NETWORK);
            }
            else {
                utils.callFunctionIfExist(onFailure, fcs.Errors.STATE);
            }
            return;
        }

        currentCallState = _callFSM.getCurrentState(internalCall);

        if (currentCallState !== fsmState.LOCAL_HOLD &&
                currentCallState !== fsmState.BOTH_HOLD) {
            if (isAutoRetried) {
                utils.callFunctionIfExist(onFailure, fcs.Errors.NETWORK);
            }
            else {
                utils.callFunctionIfExist(onFailure, fcs.Errors.STATE);
            }
            return;
        }

        if (internalCall.pendingRequestTimer) {
            utils.callFunctionIfExist(onFailure, fcs.Errors.PENDING_REQUEST);
            return;
        }

        internalCall.lastUpdateRequest = {handler: self.unhold,
            args: [callid, onSuccess, onFailure]};

        setNotificationStateOfCallToBusy(internalCall);

        self.delegateToCallFSM(internalCall, fsmNotificationEvent.unhold_GUI);
        _webRtcManager.createHoldUpdate(internalCall, false,
                (currentCallState === fsmState.BOTH_HOLD),
                function(sdp) {
                    logger.debug("[callManager.unhold->createHoldUpdate : sdp ]" + sdp);
                    _callControlService.unhold(internalCall.id, sdp,
                            function() {
                                setNotificationStateOfCallToIdle(internalCall);
                                internalCall.call.setHold(false);
                                internalCall.call.setHoldState(currentCallState);
                                //TODO: is this necessary
                                _webRtcManager.addLocalStream(internalCall);
                                utils.callFunctionIfExist(onSuccess);
                            },
                            function(err) {
                                handleRequestFailure(internalCall, onFailure,
                                        {handler: self.unhold,
                                            args: [callid, onSuccess, onFailure],
                                            timeout: err.retryAfter});
                            });
                },
                function() {
                    handleWebrtcFailure(internalCall, onFailure);
                });
    };

    self.directTransfer = function(callid, address, onSuccess, onFailure) {
        var internalCall = calls[callid], currentCallState;

        if (!internalCall) {
            utils.callFunctionIfExist(onFailure, fcs.Errors.STATE);
            return;
        }

        currentCallState = _callFSM.getCurrentState(internalCall);
        if (currentCallState === fsmState.LOCAL_HOLD
                || currentCallState === fsmState.COMPLETED
                || currentCallState === fsmState.BOTH_HOLD)
        {
            //TODO: force localhold - if the user is not on hold
            logger.info("[callManager.directTransfer->sendTransfer : transfer target ]" + address);
            _callControlService.transfer(internalCall.id, address, function() {
                self.delegateToCallFSM(internalCall, fsmNotificationEvent.transfering);
                logger.info("[callManager.directTransfer->sentTransfer : transfer target ]" + address);
            }, onFailure);
        } else {
            logger.error("directTransfer call is not in correct state: " + currentCallState);
        }
    };


    self.videoStopStart = function(callid, onSuccess, onFailure, isVideoStart, videoQuality, isAutoRetried) {
        var internalCall = calls[callid], sdp, videoSourceAllowed,
                currentCallState,
                createUpdate;

        createUpdate = function() {
            self.delegateToCallFSM(internalCall, fsmNotificationEvent.videoStopStart_GUI);
            _webRtcManager.createUpdate(
                    internalCall,
                    function(sdp) {
                        internalCall.isVideoSourceAllowed = videoSourceAllowed;
                        _callControlService.reinvite(internalCall.id, sdp,
                                function() {
                                    setNotificationStateOfCallToIdle(internalCall);
                                    //TODO: is this necessary
                                    _webRtcManager.addLocalStream(internalCall);
                                    utils.callFunctionIfExist(onSuccess);
                                },
                                function(err) {
                                    handleRequestFailure(internalCall, onFailure,
                                            {handler: self.videoStopStart,
                                                args: [callid, onSuccess, onFailure, isVideoStart, videoQuality],
                                                timeout: err.retryAfter
                                            });
                                }
                        );
                    },
                    function() {
                        logger.error("reinvite->createUpdate : sdp " + sdp);
                        handleWebrtcFailure(internalCall, onFailure);
                    },
                    isVideoStart
                    );
        };

        if (!internalCall) {
            utils.callFunctionIfExist(onFailure, fcs.Errors.STATE);
            return;
        }

        if (isNotificationStateOfCallBusy(internalCall)){
            if (isAutoRetried) {
                utils.callFunctionIfExist(onFailure, fcs.Errors.NETWORK);
            }
            else {
                utils.callFunctionIfExist(onFailure, fcs.Errors.STATE);
            }
            return;
        }

        currentCallState = _callFSM.getCurrentState(internalCall);
        if (currentCallState !== fsmState.COMPLETED) {
            if (isAutoRetried) {
                utils.callFunctionIfExist(onFailure, fcs.Errors.NETWORK);
            }
            else {
                utils.callFunctionIfExist(onFailure, fcs.Errors.STATE);
            }
            return;
        }

        if (internalCall.pendingRequestTimer) {
            utils.callFunctionIfExist(onFailure, fcs.Errors.PENDING_REQUEST);
            return;
        }

        internalCall.lastUpdateRequest = {handler: self.videoStopStart,
            args: [callid, onSuccess, onFailure, isVideoStart]};

        setNotificationStateOfCallToBusy(internalCall);

        if (!internalCall.isVideoSourceAllowed && isVideoStart) {
            self.getUserMedia(function(mediaInfo) {
                videoSourceAllowed = mediaInfo.video;
                createUpdate();
            }, function() {
                utils.callFunctionIfExist(onFailure);
            }, {
                "audio": true,
                "video": true,
                "audioIndex": 0,
                "videoIndex": 0,
                "videoResolution": videoQuality
            });
        } else {
            // avoiding videoSourceAllowed to return undefined if video source is allowed before
            videoSourceAllowed = true;
            createUpdate();
        }
    };

    self.mute = function(callid, mute) {
        var call = calls[callid], localAudioTrack;

        if (call) {
            if (!call.peer) {
                return;
            }
            logger.info("mute " + mute);
            localAudioTrack = _webRtcManager.getLocalAudioTrack(call.peer);
            if (localAudioTrack) {
                localAudioTrack.enabled = !mute;
                call.audioMuted = mute;
            }
        }
    };

    self.sendDTMF = function(callid, tone) {
        var internalCall = calls[callid];

        if (internalCall) {
            _webRtcManager.sendDTMF(internalCall, tone);
        }
    };

    self.join = function(callid1, callid2, onSuccess, onFailure) {
        var internalCall1 = calls[callid1],
                internalCall2 = calls[callid2],
                newInternalCall = {},
                isVideoEnabled = true,
                currentCallState1,
                currentCallState2;

        if ((internalCall1) && (internalCall2)) {
            currentCallState1 = _callFSM.getCurrentState(internalCall1);
            currentCallState2 = _callFSM.getCurrentState(internalCall2);
            if ((currentCallState1 === fsmState.LOCAL_HOLD
                    || currentCallState1 === fsmState.REMOTE_HOLD
                    || currentCallState1 === fsmState.BOTH_HOLD)
                    && (currentCallState2 === fsmState.LOCAL_HOLD
                    || currentCallState2 === fsmState.REMOTE_HOLD
                    || currentCallState2 === fsmState.BOTH_HOLD)) {

                self.getUserMedia(function() {
                    _webRtcManager.createOffer(newInternalCall,
                            function(sdp) {
                                logger.info("join->doOffer : sdp " + sdp);
                                newInternalCall.sdp = sdp;
                                _callControlService.join(
                                        internalCall1.id,
                                        internalCall2.id,
                                        sdp,
                                        function(callid) {

                                            newInternalCall.call = new fcs.call.OutgoingCall(callid);
                                            newInternalCall.id = callid;

                                            newInternalCall.onIceStateFailure = function(sdp) {
                                                self.onIceStateFailure(newInternalCall, sdp);
                                            };

                                            // refer will be handled by client. We are going to need callID of partyB and partyC
                                            if (fcsConfig.clientControlled === "true") {
                                                newInternalCall.isReferer = true;
                                                newInternalCall.refer1ID = internalCall1.id;
                                                newInternalCall.refer2ID = internalCall2.id;
                                            }

                                            self.delegateToCallFSM(internalCall1, fsmNotificationEvent.joining_Notify);
                                            self.delegateToCallFSM(internalCall2, fsmNotificationEvent.joining_Notify);
                                            self.delegateToCallFSM(newInternalCall, fsmNotificationEvent.joiningSuccess_Notify);
                                            calls[callid] = newInternalCall;

                                            utils.callFunctionIfExist(onSuccess, newInternalCall.call);
                                        }, function() {
                                    logger.error("callControlService.join Failed!! sdp " + sdp);
                                    utils.callFunctionIfExist(onFailure);
                                });
                            }, function() {
                        logger.error("doOffer Failed!!");
                        utils.callFunctionIfExist(onFailure);
                    }, false);
                }, function() {
                    utils.callFunctionIfExist(onFailure);
                }, {
                    "audio": true,
                    "video": isVideoEnabled ? true : false,
                    "audioIndex": 0,
                    "videoIndex": isVideoEnabled ? 0 : -1
                });
            }
        }
    };

    self.transfer = function(callid, address, onSuccess, onFailure) {

    };

    self.end = function(callid, onSuccess) {
        var internalCall = calls[callid];
        if (internalCall) {
            //check with the state machine if the current state would accept an endCall.
            if (_callFSM.getCurrentState(internalCall) === fsmState.INIT) {
                logger.error("Cannot end call in INIT callstate :" + fcs.Errors.STATE);
            } else {
                //send the end call to webrtc abstraction, change call state
                //this will trigger the send endcall or reject call
                self.delegateToCallFSM(internalCall, fsmNotificationEvent.end_GUI);

                clearResources(internalCall);
                utils.callFunctionIfExist(onSuccess);
            }
        }

    };

    self.incomingCall = function(call, sdp) {

        logger.info("incomingCall : sdp = " + sdp);
        var internalCall = {
            "call": call,
            "sdp": sdp,
            "id": call.getId()
        };
        logger.info("incomingCall: " + call.getId());

        if (fcsConfig.continuity && call.canAnswer()) {
            cacheCall(internalCall);
        }

        calls[call.getId()] = internalCall;
        call.isIceLite = _sdpParser.isIceLite(sdp);
        self.delegateToCallFSM(internalCall, fsmNotificationEvent.callNotify);
    };


    self.updateCall = function() {
    };

    self.onNotificationEvent = function(type, sessionParams) {
        var callid = sessionParams.sessionData,
                statusCode = sessionParams.statusCode,
                reasonText = sessionParams.reasonText,
                sdp = sessionParams.sdp,
                referTo = sessionParams.referTo,
                referredBy = sessionParams.referredBy,
                retryAfter = sessionParams.retryAfter;

        logger.debug("Notification received " + type + " callid:" + callid);
        logger.debug("onNotificationEvent : sdp " + sdp);
        if (calls[callid]) {
            if(isQueueEnabled && isNotificationStateOfCallBusy(calls[callid])){
                logger.debug("NOTIFICATION_QUEUE: notification state is busy, adding process to the queue!");
                calls[callid].call.notificationQueue.enqueue({
                    type: type,
                    sessionParams: sessionParams
                });
                logger.debug("NOTIFICATION_QUEUE: queue size is now " + calls[callid].call.notificationQueue.size());
                return;
            }

            if(isQueueEnabled){
                setNotificationStateOfCallToBusy(calls[callid]);
            }

            if (sdp) {
                calls[callid].prevRemoteSdp = calls[callid].sdp;
                sdp = _sdpParser.deleteGoogleIceFromSdp(sdp);
                calls[callid].sdp = sdp;
            }
            if (referTo && referredBy) {
                calls[callid].referTo = referTo;
                calls[callid].referredBy = referredBy;
            }
            calls[callid].isIceLite = _sdpParser.isIceLite(sdp);
            calls[callid].retryAfter = retryAfter;
            calls[callid].statusCode = statusCode;
            calls[callid].reasonText = reasonText;
        }
        self.delegateToCallFSM(calls[callid], type);
    };

    self.onStateChange = function(call, event) {
        var callStates = CALL_STATES,
                transferEvent = _callFSM.TransferEvent,
                i, isJoin, isLocalHold, auditTimerDelay, startAuditTimer;

        calls[call.id] = call;


        function triggerCallState(state, doNotTriggerQueue) {
            logger.debug("triggerCallState:  state =   " + state + "    call.statusCode =  " + call.statusCode + "   call.reasonText =  " + call.reasonText);
            call.call.callState = state;
            utils.callFunctionIfExist(call.call.onStateChange, state, call.statusCode, call.reasonText);
            if (!doNotTriggerQueue) {
                triggerQueue(call);
            }
        }

        function triggerCallStateWithoutQueue(state) {
            triggerCallState(state, true);
        }

        auditTimerDelay = function() {
            setTimeout(function() {
                if (fcs.isConnected()) {
                    _callControlService.audit(call.id, function() {
                        logger.info("Audit kicked off: Success for: " + call.id);
                    }, function() {
                        logger.error("Audit: Fail for: " + call.id);
                        // no need to end the call after audit fail
                        // clearResources(call);
                        // triggerCallState(callStates.ENDED);
                    });
                }
            }, AUDIT_KICKOFF_TIMEOUT);
        };

        startAuditTimer = function() {
            call.call.setAuditTimer(function() {
                if (fcs.isConnected()) {
                    _callControlService.audit(call.id, function() {
                        logger.info("Audit: Success for: " + call.id);
                    }, function() {
                        logger.error("Audit: Fail for: " + call.id);
                        // no need to end the call after audit fail
                        // clearResources(call);
                        // triggerCallState(callStates.ENDED);
                        triggerQueue(call);
                    });
                }
            });
        };

        logger.info("Transfer Event: " + event + ". callId: " + call.id);
        switch (event) {
            case transferEvent.callStart_fsm:
            case transferEvent.localHolding_fsm:
            case transferEvent.localUnHolding_fsm:
            case transferEvent.localVideoStopStart_fsm:
            case transferEvent.slowStartOfferProcessed_fsm:
            case transferEvent.joiningSuccess_fsm:
                break;
            case transferEvent.ignoredNotification_fsm:
            case transferEvent.answeringRingingSlow_fsm:
            case transferEvent.transfering_fsm:
            case transferEvent.localHold_fsm:
            case transferEvent.localUnHold_fsm:
                triggerQueue(call);
                break;
            case transferEvent.ringing_fsm:
                triggerCallState(callStates.RINGING);
                break;
            case transferEvent.callReceived_fsm:
                if (!(call.sdp)) {
                    self.delegateToCallFSM(call, fsmNotificationEvent.callNotify_noSDP);
                }
                triggerCallState(callStates.INCOMING);
                break;
            case transferEvent.answer_fsm:
                auditTimerDelay();
                startAuditTimer();
                break;
            case transferEvent.answerRingingSlow_fsm:
                triggerQueue(call);
                break;
            case transferEvent.reject_GUI:
                clearResources(call);
                break;
            case transferEvent.sessionComplete_fsm:
                _callControlService.endCall(call.id, function() {
                    logger.info("callControlService.endCall successful. callId: " + call.id);
                }, function() {
                    logger.error("callControlService.endCall FAILED!!.callId: " + call.id);
                });
                clearResources(call);
                triggerCallState(callStates.JOINED);
                break;
            case transferEvent.sessionFail_fsm:
                triggerCallState(callStates.ON_HOLD);
                break;
            case transferEvent.callCompleted_fsm:
                //startCall case: this is place where we must
                //have already got the remote sdp so need to let webrtc
                //process answer with latest sdp
                auditTimerDelay();
                _webRtcManager.processAnswer(call, function() {
                    startAuditTimer();
                    triggerCallState(callStates.IN_CALL);
                }, function() {
                    clearResources(call);
                    triggerCallState(callStates.ENDED);
                });

                //if client is handling the refers, we need to trigger the refers for partyB and partyC from referer
                if (call.isReferer) {
                    for (i in calls) {
                        if (calls.hasOwnProperty(i)) {
                            if (calls[i] && (calls[i].id === call.refer1ID || calls[i].id === call.refer2ID)) {
                                calls[i].referCall(call.referTo, call.referredBy);
                            }
                        }
                    }
                }
                break;
            case transferEvent.noAnswer_fsm:
                clearResources(call);
                triggerCallState(callStates.ENDED);
                break;
            case transferEvent.localEnd_fsm:
                _callControlService.endCall(call.id, function() {
                    logger.info("CallControlService endCall successful. callId: " + call.id);
                }, function() {
                    logger.error("Cannot callControlService endCall. callId: " + call.id);
                });
                break;
            case transferEvent.callCompletedAnswering_fsm:
                logger.info("callManager: Call Completed Answering Event. callId: " + call.id);
                _webRtcManager.processAnswer(call, function() {
                    triggerCallState(callStates.IN_CALL);
                    auditTimerDelay();
                    startAuditTimer();
                }, function() {
                    clearResources(call);
                    triggerCallState(callStates.ENDED);
                });
                break;
            case transferEvent.remoteEnd_fsm:
                //clear webRTC resources
                clearResources(call);
                triggerCallState(callStates.ENDED);
                break;
            case transferEvent.remoteHold_fsm:
                call.call.setHold(true);
                call.call.setHoldState(_callFSM.getCurrentState(call));
                switch (_callFSM.getCurrentState(call)) {
                    case fsmState.REMOTE_HOLD:
                        triggerCallState(callStates.ON_REMOTE_HOLD);
                        break;
                    case fsmState.BOTH_HOLD:
                        triggerCallState(callStates.ON_HOLD);
                        break;
                    default:
                        triggerQueue(call);
                        break;
                }
                break;
            case transferEvent.remoteUnHold_fsm:
                call.call.setHold(false);
                call.call.setHoldState(_callFSM.getCurrentState(call));
                switch (_callFSM.getCurrentState(call)) {
                    case fsmState.LOCAL_HOLD:
                        triggerCallState(callStates.ON_HOLD);
                        break;
                    case fsmState.COMPLETED:
                        triggerCallState(callStates.IN_CALL);
                        break;
                    default:
                        triggerQueue(call);
                        break;
                }
                break;
            case transferEvent.remoteHolding_fsm:
                isLocalHold = (_callFSM.getCurrentState(call) === fsmState.LOCAL_HOLD) || (_callFSM.getCurrentState(call) === fsmState.BOTH_HOLD);
                _webRtcManager.processHold(call, true, isLocalHold, function(sdp) {
                    logger.info("[callManager.onStateChange.transferEvent.remoteHold_fsm->processHold : sdp ]" + sdp);
                    _callControlService.respondCallUpdate(call.id, sdp, function() {
                        logger.info("Remote Hold Transfer Event Successful. callId: " + call.id);
                        self.delegateToCallFSM(call, fsmNotificationEvent.remoteHoldProcessed_JSL);
                    }, function(errorStr) {
                        logger.error("Remote Hold Transfer Event FAILED!! - " + errorStr);
                        handleRequestFailure(call);
                    });
                }, function(errorStr) {
                    logger.error("Remote Hold FAILED!! - " + errorStr);
                    handleWebrtcFailure(call);
                });
                break;
            case transferEvent.remoteOfferDuringLocalHold_fsm:
                _webRtcManager.processRemoteOfferOnLocalHold(call, function(sdp) {
                    logger.info("onStateChange.transferEvent.remoteOfferDuringLocalHold_fsm : sdp " + sdp);
                    _callControlService.respondCallUpdate(call.id, sdp, function() {
                        logger.info("Remote Offer During Local Hold Transfer Event successful. callId: " + call.id);
                        triggerQueue(call);
                    }, function(errorStr) {
                        handleRequestFailure(call);
                        logger.error("Remote Offer During Local Hold  Transfer Event FAILED!! - " + errorStr);
                    });
                }, function(errorStr) {
                    logger.error("Remote Offer During Local Hold FAILED!! - " + errorStr);
                    handleWebrtcFailure(call);
                });
                break;
            case transferEvent.slowStartOfferDuringOnCall_fsm:
            case transferEvent.slowStartOfferDuringRemoteHold_fsm:
                _webRtcManager.createReOffer(call, function(sdp) {
                    logger.info("onStateChange.transferEvent.createReOffer: sdp " + sdp);
                    _callControlService.respondCallUpdate(call.id, sdp, function() {
                        logger.info("Slow Start Offer respondCallUpdate successful. callId: " + call.id);
                        self.delegateToCallFSM(call, fsmNotificationEvent.slowStartOfferProcessed_JSL);
                        triggerQueue(call);
                    }, function(errorStr) {
                        logger.error("Slow Start Offer respondCallUpdate FAILED!! - " + errorStr);
                        handleRequestFailure(call);
                    });
                }, function(errorStr) {
                    logger.error("Slow Start Offer createReOffer FAILED!! - " + errorStr);
                    handleWebrtcFailure(call);
                }, true);
                break;
            case transferEvent.sendReInvite_fsm:
                _webRtcManager.createReOffer(call, function(sdp) {
                    logger.info("onStateChange.transferEvent.createReOffer : sdp " + sdp);
                    _callControlService.reinvite(call.id, sdp, function() {
                        setNotificationStateOfCallToIdle(call);
                        logger.info("callControlService.reinvite successful. callId: " + call.id);
                    }, function() {
                        self.delegateToCallFSM(call, fsmNotificationEvent.requestFailure_JSL);
                    });
                }, function(errorStr) {
                    handleWebrtcFailure(call);
                }, true);
                break;
            case transferEvent.performReconnectWorkaround_fsm:
                _webRtcManager.performReconnectWorkaround(call, function performReconnectWorkaroundSuccessCallback(sdp)
                {
                    logger.info("onStateChange.transferEvent.performReconnectWorkaround : sdp " + sdp);
                    _callControlService.reinvite(call.id, sdp, function reInviteSuccessCallback() {
                        setNotificationStateOfCallToIdle(call);
                        _webRtcManager.addLocalStream(call);
                        logger.info("callControlService.reinvite successful. callId: " + call.id);
                    }, function() {
                        self.delegateToCallFSM(call, fsmNotificationEvent.requestFailure_JSL);
                    });
                }, function(errorStr) {
                    handleWebrtcFailure(call);
                });
                break;
            case transferEvent.remoteUnHolding_fsm:
                isLocalHold = (call.previousState === fsmState.LOCAL_HOLD) || (call.previousState === fsmState.BOTH_HOLD);
                _webRtcManager.processHold(call, false, isLocalHold, function(sdp) {
                    logger.info("onStateChange.transferEvent.remoteUnHold_fsm->processHold : sdp " + sdp);
                    _callControlService.respondCallUpdate(call.id, sdp, function() {
                        logger.info("Remote UnHold Transfer Event successful. callId: " + call.id);
                        self.delegateToCallFSM(call, fsmNotificationEvent.remoteUnHoldProcessed_JSL);
                    }, function(errorStr) {
                        logger.error("Remote UnHold Transfer Event FAILED!! - " + errorStr);
                        handleRequestFailure(call);
                    });
                }, function(errorStr) {
                    logger.error("Remote UnHold FAILED!! - " + errorStr);
                    handleWebrtcFailure(call);
                });
                break;
            case transferEvent.renegotiationCompleted_fsm:
                triggerCallState(callStates.RENEGOTIATION);
            break;
            case transferEvent.remoteOffer_fsm:
            case transferEvent.remoteCallUpdate_fsm:
                _webRtcManager.processUpdate(call, function(sdp) {
                    logger.info("onStateChange.transferEvent.remoteCallUpdate_fsm->processUpdate : sdp " + sdp);
                    _callControlService.respondCallUpdate(call.id, sdp, function() {
                        logger.info("Remote Call Update Transfer Event Successful. callId: " + call.id);
                        self.delegateToCallFSM(call, fsmNotificationEvent.remoteOfferProcessed_JSL);
                    }, function(errorStr) {
                        logger.error("Remote Call Update Transfer Event FAILED!! - " + errorStr);
                        handleRequestFailure(call);
                    });
                }, function(errorStr) {
                    logger.error("Remote Call Update FAILED!! - " + errorStr);
                    handleWebrtcFailure(call);
                }, call.currentState === fsmState.LOCAL_HOLD ? true : false);
                break;
            case transferEvent.respondCallHoldUpdate_fsm:
                isJoin = call.call.getJoin();
                _webRtcManager.processHoldRespond(call, function() {
                    logger.info("Respond Call Hold Update Event Successful. callId: " + call.id);
                    call.call.setHold(true);
                    call.call.setHoldState(_callFSM.getCurrentState(call));
                    switch (_callFSM.getCurrentState(call)) {
                        case fsmState.REMOTE_HOLD:
                            triggerCallState(callStates.ON_REMOTE_HOLD);
                            break;
                        case fsmState.LOCAL_HOLD:
                        case fsmState.BOTH_HOLD:
                            triggerCallState(callStates.ON_HOLD);
                            break;
                        case fsmState.COMPLETED:
                            call.call.setHold(false);
                            call.call.setHoldState(null);
                            triggerCallState(callStates.IN_CALL);
                            break;
                    }
                    //triggerCallState(callStates.RENEGOTIATION);
                }, function(e) {
                    logger.error("Respond Call Hold Update Event FAILED: " + e);
                    triggerQueue(call);
                }, isJoin);

                //enable clicking
                call.call.setButtonDisabler(false);
                call.call.clearBtnTimeout();

                if (isJoin === true) {
                    call.call.onJoin();
                }

                break;
            case transferEvent.respondCallUpdate_fsm:
                isJoin = call.call.getJoin();

                //enable clicking
                call.call.setButtonDisabler(false);
                call.call.clearBtnTimeout();

                //If this is a join call we need to send join request
                //onJoin() function is created at callController.js
                if (isJoin === true) {
                    _webRtcManager.processRespond(call, function() {
                        logger.info("Respond Call Update Event Successful. callId: " + call.id);
                        triggerCallState(callStates.RENEGOTIATION);
                    }, function(e) {
                        logger.error("Respond Call Update Event FAILED: " + e);
                        triggerQueue(call);
                    }, isJoin);

                    call.call.onJoin();
                } else {
                    _webRtcManager.processRespond(call, function() {
                        logger.info("Respond Call Update Event Successful. callId: " + call.id);
                        triggerCallState(callStates.IN_CALL);
                    }, function(e) {
                        logger.error("Respond Call Update Event FAILED: " + e);
                        triggerQueue(call);
                    }, isJoin);
                }
                break;
            case transferEvent.preCallResponse_fsm:
                _webRtcManager.processPreAnswer(call);
                triggerCallState(callStates.RINGING);
                break;
            case transferEvent.forward_fsm:
                clearResources(call);
                break;
            case transferEvent.joining_fsm:
                //if client is handling the refers from referer we need to trigger the refers for partyB and partyC
                if (fcsConfig.clientControlled === "true") {
                    call.referCall = function(referTo, referredBy) {
                        _callControlService.refer(call.id, referTo, referredBy, function() {
                            logger.info("Joining Event Successful. callId: " + call.id);
                            self.delegateToCallFSM(call, fsmNotificationEvent.refer_JSL);
                        }, function(errorStr) {
                            logger.error("Joining Event FAILED!!" + errorStr);
                        });
                    };
                }
                triggerQueue(call);
                break;
            case transferEvent.transferSuccess_fsm:
                _callControlService.endCall(call.id, function() {
                    logger.info("callControlService.endCall successful. callId: " + call.id);
                }, function() {
                    logger.error("callControlService.endCall FAILED!! callId: " + call.id);
                });
                clearResources(call);
                triggerCallState(callStates.TRANSFERRED);
                logger.info("endCall successful. callId: " + call.id);
                break;
            case transferEvent.transferFail_fsm:
                triggerCallState(callStates.ON_HOLD);
                break;
            case transferEvent.stateReverted_fsm:
                //enable clicking
                call.call.setButtonDisabler(false);
                call.call.clearBtnTimeout();

                call.call.setHold(false);
                call.call.setHoldState(null);

                switch (_callFSM.getCurrentState(call)) {
                    case fsmState.REMOTE_HOLD:
                        call.call.setHold(true);
                        call.call.setHoldState(_callFSM.getCurrentState(call));
                        triggerCallStateWithoutQueue(callStates.ON_REMOTE_HOLD);
                        break;
                    case fsmState.BOTH_HOLD:
                        call.call.setHold(true);
                        call.call.setHoldState(_callFSM.getCurrentState(call));
                        triggerCallStateWithoutQueue(callStates.ON_HOLD);
                        break;
                    case fsmState.LOCAL_HOLD:
                        call.call.setHold(true);
                        call.call.setHoldState(_callFSM.getCurrentState(call));
                        triggerCallStateWithoutQueue(callStates.ON_HOLD);
                        break;
                    case fsmState.COMPLETED:
                        triggerCallStateWithoutQueue(callStates.IN_CALL);
                        break;
                    default:
                        logger.error("CANNOT REVERT THE STATE: " + _callFSM.getCurrentState(call) + ". callId: " + call.id);
                        break;
                }
                break;
            case transferEvent.glareCondition_fsm:
                handleFailure(call, null, null, {
                    handler: call.lastUpdateRequest.handler,
                    args: call.lastUpdateRequest.args,
                    timeout: call.retryAfter});
                break;
            default:
                logger.error("Undefined transition event: " + event + " for " + call.id);
                triggerQueue(call);
                break;

        }

    };

    self.refreshVideoRenderer = function(callid) {
        var internalCall = calls[callid];
        if (internalCall) {
            _webRtcManager.refreshVideoRenderer(internalCall);
        }
    };

    self.hasVideoDevice = function() {
        return _webRtcManager.isVideoSourceAvailable();
    };

    self.hasAudioDevice = function() {
        return _webRtcManager.isAudioSourceAvailable();
    };

    self.getLocalVideoResolutions = function() {
        return _webRtcManager.getLocalVideoResolutions();
    };

    self.getRemoteVideoResolutions = function() {
        return _webRtcManager.getRemoteVideoResolutions();
    };

    self.isCallMuted = function(callid) {
        var call = calls[callid];
        if (call && call.audioMuted) {
            return call.audioMuted;
        }
        return false;
    };

    self.isVideoNegotationAvailable = function(callid) {
        var call = calls[callid];
        if (call.sdp){
            return _sdpParser.isSdpHasVideo(call.sdp);
        } else {
            return false;
        }
    };

    self.getRemoteVideoState = function(callid) {
        var call = calls[callid];
        return call.remoteVideoState;
    };

    self.onIceStateFailure = function(internalCall) {
        if (internalCall) {
            setNotificationStateOfCallToBusy(internalCall);
            self.delegateToCallFSM(internalCall, fsmNotificationEvent.sendReInvite_JSL);
        }
    };

    self.getHoldStateOfCall = function(callid) {
        var internalCall = calls[callid];
        if (internalCall) {
            return CALL_HOLD_STATES[_callFSM.getCurrentState(internalCall)];
        }
        return undefined;
    };

    NotificationCallBacks.call = function handleIncomingCall(data) {
        // disabling the notifications for verizon demo
        if (!fcs.notification.isAnonymous()) {
            var sdp, actions, params, calls, remoteConversationId,
                    call = null,
                    callid = null,
                    options = {},
                    callParams = data.callNotificationParams,
                    dispositionParams = data.callDispositionParams,
                    sessionParams = data.sessionParams;

            //Since session also include disposition use it as default
            params = sessionParams ? sessionParams : (dispositionParams ? dispositionParams : null);
            logger.info("params: " + params);

            if (params) {
                actions = params.actions;
                logger.info("actions: " + actions);
                if (params.sessionData) {
                    callid = params.sessionData;
                    calls = self.getCalls();
                    if (calls[callid] !== undefined) {
                        logger.info("call already exists: " + callid);
                        return;
                    }
                    logger.info("sessionData: " + callid);
                }
                if (actions) {
                    options.reject = (actions.indexOf("reject", 0) > -1);
                    options.forward = (actions.indexOf("forward", 0) > -1);
                    options.answer = (actions.indexOf("answer", 0) > -1);
                }
                if (params.sdp) {
                    sdp = params.sdp;
                }
                if (params.conversation) {
                    remoteConversationId = params.conversation;
                }
            }

            call = new fcs.call.IncomingCall(callid, options);
            if (remoteConversationId && remoteConversationId.indexOf("convid=") > -1) {
                call.remoteConversationId = remoteConversationId.split("convid=")[1].split(",")[0];
            }
            call.callerNumber = utils.getProperty(callParams, 'callerDisplayNumber');
            call.callerName = utils.getProperty(callParams, 'callerName');
            call.calleeNumber = utils.getProperty(callParams, 'calleeDisplayNumber');
            call.primaryContact = utils.getProperty(callParams, 'primaryContact');
            if (call.primaryContact) {
                call.primaryContact = call.primaryContact.split(";")[0];
            }

            //create the call in the state machine
            self.incomingCall(call, sdp);

            //notify the callback
            utils.callFunctionIfExist(fcs.call.onReceived, call);
        }
    };

    function handleCallControlNotification(type, data) {
        var sessionParams = data.sessionParams;
        logger.info("CallControl notification received " + type + " sessionData:" + sessionParams.sessionData);
        if (sessionParams.referTo) {
            logger.info("CallControl notification received: " + "referTo:" + sessionParams.referTo + " referredBy: " + sessionParams.referredBy);
        }
        if (sessionParams) {
            self.onNotificationEvent(type, sessionParams);
        }
    }

    NotificationCallBacks.ringing = function(data) {
        handleCallControlNotification(fsmNotificationEvent.ringing_Notify, data);
    };

    NotificationCallBacks.sessionProgress = function(data) {
        //We are discarding the sessionProgress if the SDP is empty
        if (data.sessionParams.sdp !== "") {
            handleCallControlNotification(fsmNotificationEvent.sessionProgress, data);
        }
        else {
            logger.info("Warning: SDP of sessionProgress is empty.");
        }
    };

    NotificationCallBacks.startCallUpdate = function handleStartCallUpdateNotification(data) {
        var sdp = data.sessionParams.sdp,
                notificationEvent = fsmNotificationEvent.startCallUpdate_slowStart_Notify;
        if (sdp) {
            _sdpParser.init(sdp);
            if (_sdpParser.isRemoteHold()) {
                notificationEvent = fsmNotificationEvent.startCallUpdate_remoteHold_Notify;
            }
            else {
                notificationEvent = fsmNotificationEvent.startCallUpdate_remoteOffer_Notify;
            }
        }
        handleCallControlNotification(notificationEvent, data);
    };

    NotificationCallBacks.respondCallUpdate = function handleRespondCallUpdateNotification(data) {
        if (data.sessionParams && data.sessionParams.retryAfter) {
            handleCallControlNotification(fsmNotificationEvent.respondCallUpdate_glareCondition_Notify, data);
        }
        else {
            handleCallControlNotification(fsmNotificationEvent.respondCallUpdate_Notify, data);
        }
    };

    NotificationCallBacks.sessionComplete = function handleSssionCompleteNotification(data) {
        handleCallControlNotification(fsmNotificationEvent.sessionComplete_Notify, data);
    };

    NotificationCallBacks.sessionFail = function handleSessionFailNotification(data) {
        handleCallControlNotification(fsmNotificationEvent.sessionFail_Notify, data);
    };

    NotificationCallBacks.callEnd = function handleCallEndNotification(data) {
        handleCallControlNotification(fsmNotificationEvent.callEnd_Notify, data);
    };

    NotificationCallBacks.trying = function handleTryingNotification(data) {
        handleCallControlNotification(fsmNotificationEvent.trying_Notify, data);
    };

    NotificationCallBacks.callCancel = function handleCallCancelNotification(data) {
        handleCallControlNotification(fsmNotificationEvent.callCancel_Notify, data);
    };

    NotificationCallBacks.accepted = function handleAcceptedNotification(data) {
        handleCallControlNotification(fsmNotificationEvent.accepted_Notify, data);
    };

    globalBroadcaster.subscribe(CONSTANTS.EVENT.DEVICE_SUBSCRIPTION_STARTED, onSubscriptionReEstablished);
    globalBroadcaster.subscribe(CONSTANTS.EVENT.CONNECTION_REESTABLISHED, onConnectionLost);
    globalBroadcaster.subscribe(CONSTANTS.EVENT.NOTIFICATION_CHANNEL_LOST, onConnectionLost);
    if (__testonly__) { self.setCalls = function(_calls){ calls=_calls;}; }
};
var callManager = new CallManager(webRtcManager, callFSM, callControlService, sdpParser, logManager);
//will be removed
fcs.callManager = callManager;
//TODO define a testonly setCalls method
if (__testonly__) { __testonly__.CallManager = CallManager; }

/**
* Provides access to a user's call log.
*
* @name calllog
* @namespace
* @memberOf fcs
*
* @version 3.0.4
* @since 3.0.0
*/
var Calllog = function(){

   /**
    * Enum for the type of call log.
    * @name CallTypes
    * @enum {number}
    * @since 3.0.0
    * @readonly
    * @memberOf fcs.calllog
    * @property {number} [INCOMING=0] Incoming call.
    * @property {number} [MISSED=1] Missed call.
    * @property {number} [OUTGOING=2] Outgoing call.
    */
    this.CallTypes = {

        INCOMING: 0,

        MISSED: 1,

        OUTGOING: 2
    };

   /**
    * Retrieves the list of call logs from the server.
    *
    * @name fcs.calllog.retrieve
    * @function
    * @since 3.0.0
    * @param {function} onSuccess The onSuccess({@link Array.<fcs.calllog.Entry>}) callback to be called
    * @param {function} onFailure The onFailure({@link fcs.Errors}) callback to be called
    * @param {number} [startIndex=0] starting offset within the list of log records (records before this offset will not be returned)
    * @param {number} [count=100] The number of the log records to be returned
    *
    * @example
    * var onSuccess = function(data){
    *    var i = 0;
    *    for (i in data) {
    *       window.console.log("call log record id: " + data[i].id + " entry: ", data);
    *    }
    * };
    * var onError = function (err) {
    *   //do something here
    * };
    *
    * fcs.calllog.retrieve(onSuccess, onError);
    * OR
    * fcs.calllog.retrieve(onSuccess, onError, 10);
    * OR
    * fcs.calllog.retrieve(onSuccess, onError, 10, 50);
    */


   /**
    * Deletes a call log from the server.
    *
    * @name fcs.calllog.remove
    * @function
    * @since 3.0.0
    * @param {string} calllogid The id of the call log to be deleted
    * @param {function} onSuccess The onSuccess() callback to be called
    * @param {function} onFailure The onFailure({@link fcs.Errors}) callback to be called
    *
    * @example
    * var onSuccess = function(){
    *    //do something here
    * };
    * var onError = function (err) {
    *   //do something here
    * };
    *
    * fcs.calllog.remove("calllogid", onSuccess, onError);
    */

   /**
    * Clears the entire call log from the server.
    *
    * @name fcs.calllog.removeAll
    * @function
    * @since 3.0.0
    * @param {function} onSuccess The onSuccess() callback to be called
    * @param {function} onFailure The onFailure({@link fcs.Errors}) callback to be called
    *
    * @example
    * var onSuccess = function(){
    *    //do something here
    * };
    * var onError = function (err) {
    *   //do something here
    * };
    *
    * fcs.calllog.removeAll( onSuccess, onError);
    */

   /**
    * @name Entry
    * @class
    * @memberOf fcs.calllog
    * @version 3.0.4
    * @since 3.0.0
    */
    this.Entry = function(){};

   /**
    * Unique record id of log.
    *
    * @name fcs.calllog.Entry#id
    * @field
    * @since 3.0.0
    * @type {String}
    */

   /**
    * Display number of caller.
    *
    * @name fcs.calllog.Entry#address
    * @field
    * @since 3.0.0
    * @type {String}
    */

   /**
    * Name of caller.
    *
    * @name fcs.calllog.Entry#name
    * @field
    * @since 3.0.0
    * @type {String}
    */

   /**
    * Duration of call.
    *
    * @name fcs.calllog.Entry#duration
    * @field
    * @since 3.0.0
    * @type {String}
    */

   /**
    * Start time of call.
    *
    * @name fcs.calllog.Entry#startTime
    * @field
    * @since 3.0.0
    * @type {Date}
    */

   /**
    * Type of call.
    *
    * @name fcs.calllog.Entry#type
    * @field
    * @since 3.0.0
    * @type {fcs.calllog.CallTypes}
    */
};
var Calllogimpl = function() {

    var clUrl = "/logHistory",
        lrUrl = "/logRecord/",
        callTypes = {},
        callTypesEnum = this.CallTypes,
        DEFAULT_START_INDEX = 0,
        DEFAULT_COUNT = 100;

    callTypes.incoming = callTypesEnum.INCOMING;
    callTypes.outgoing = callTypesEnum.OUTGOING;
    callTypes.missed = callTypesEnum.MISSED;

    function parseData(data) {
        var i, logs = [], log, params, type, date;
        if(data && data.logHistory && data.logHistory.logItems){
            for(i=0; i < data.logHistory.logItems.length;i++){
                params = data.logHistory.logItems[i].params;
                log =  new fcs.calllog.Entry(params);

                log.id = utils.getProperty(params, 'recordId');
                log.address = utils.getProperty(params, 'callerDisplayNumber');
                log.name = utils.getProperty(params, 'callerName');
                log.duration = utils.getProperty(params, 'duration');

                // convert string timestamp to Date object
                date = parseInt(params.startTime, 10);
                log.startTime = isNaN(date) ? null : new Date(date);

                // convert wam value to fcs.calllog.CallTypes value
                log.type = null;
                type = utils.getProperty(params, 'direction');
                if(type !== null && callTypes[type] !== undefined){
                    log.type = callTypes[type];
                }

                logs.push(log);
            }
            // We need to sort *logs array to view call logs in descending time order inside CallLogTab
            logs = logs.sort(function(a,b){return b.startTime - a.startTime;});
        }

        return logs;
    }

    function composeRetreiveData(startIndex, count) {
        var data = {startIndex: DEFAULT_START_INDEX,
            count: DEFAULT_COUNT};

        if (startIndex) {
            if (startIndex.trim) {
                startIndex.trim();
            }

            if (isFinite(startIndex) && startIndex >= 0 && startIndex !== "") {
                data.startIndex = startIndex;
            }
        }

        if (count) {
            if (count.trim) {
                count.trim();
            }

            if (isFinite(count) && count >= 0 && count !== "") {
                data.count = count;
            }
        }

        return data;
    }

    this.retrieve = function(onSuccess, onFailure, startIndex, count) {
        server.sendGetRequest({
                url: getWAMUrl(1, clUrl),
                "data": composeRetreiveData(startIndex, count)
            },
            onSuccess,
            onFailure,
            parseData
        );

    };

    this.retrievePartial = function(startIndex, count, onSuccess, onFailure) {
        server.sendGetRequest({
                url: getWAMUrl(1, clUrl),
                "data": composeRetreiveData(startIndex, count)
            },
            onSuccess,
            onFailure,
            parseData
        );

    };

    this.removeAll = function(onSuccess, onFailure) {

        server.sendDeleteRequest({
                url: getWAMUrl(1, clUrl)
            },
            onSuccess,
            onFailure
        );
    };

    this.remove = function(calllogid,onSuccess, onFailure) {

        server.sendDeleteRequest({
                url: getWAMUrl(1, lrUrl + calllogid)
            },
            onSuccess,
            onFailure
        );
    };
};

Calllogimpl.prototype = new Calllog();

fcs.calllog = new Calllogimpl();

var Addressbookimpl = function() {

    this.retrieve = function(parseData, onSuccess, onFailure) {
        server.sendGetRequest({
                    url: getWAMUrl(1, "/addressbook")
                },
                onSuccess,
                onFailure,
                parseData,
                undefined,
                "addressBookResponse");
    };

    this.searchDirectory = function(criteria, searchType, parseData, onSuccess, onFailure) {

        server.sendGetRequest({
                    "url": getWAMUrl(1, "/directory"),
                    "data": {"criteria": criteria, "criteriaType": searchType}
                },
                onSuccess,
                onFailure,
                parseData);
    };
};

var addressbookService = new Addressbookimpl();

var AddressbookManager = function() {
    var SearchType = {
        FIRSTNAME: 0,
        LASTNAME: 1,
        NAME: 2,
        PHONENUMBER: 3,
        USERNAME: 4,
        NA: 5
    }, Entry = function() {
    }, searchTypes = {};

    searchTypes[SearchType.FIRSTNAME] = "1";
    searchTypes[SearchType.LASTNAME] = "2";
    searchTypes[SearchType.NAME] = "3";
    searchTypes[SearchType.PHONENUMBER] = "4";
    searchTypes[SearchType.USERNAME] = "5";
    searchTypes[SearchType.NA] = "-1";

    function parseData(result) {
        var i, entries = [], entry, params, items;
        if (result) {
            if (result.directory) {
                items = result.directory.directoryItems;
            } else if (result.addressBookResponse) {
                items = result.addressBookResponse.addressBookEntries;
            }

            if (items) {
                for (i = 0; i < items.length; i++) {
                    params = items[i];
                    entry = new Entry();

                    entry.id = utils.getProperty(params, 'entryId');
                    entry.nickname = utils.getProperty(params, 'nickname');
                    entry.primaryContact = utils.getProperty(params, 'primaryContact');
                    entry.firstName = utils.getProperty(params, 'firstName');
                    entry.lastName = utils.getProperty(params, 'lastName');
                    entry.photoUrl = utils.getProperty(params, 'photoUrl');
                    entry.email = utils.getProperty(params, 'emailAddress');
                    entry.homePhone = utils.getProperty(params, 'homePhone');
                    entry.mobilePhone = utils.getProperty(params, 'mobilePhone');
                    entry.workPhone = utils.getProperty(params, params.workPhone ? 'workPhone' : 'businessPhone');
                    entry.friendStatus = utils.getProperty(params, 'friendStatus');
                    entry.accessCode = utils.getProperty(params, 'conferenceURL');
                    if (!entry.friendStatus) {
                        entry.friendStatus = false;
                    }
                    entry.fax = utils.getProperty(params, 'fax');
                    entry.pager = utils.getProperty(params, 'pager');

                    entries.push(entry);
                }
            }
        }

        return entries;
    }

    this.Entry = Entry;

    this.SearchType = SearchType;

    this.retrieve = function(onSuccess, onFailure) {
        addressbookService.retrieve(parseData, onSuccess, onFailure);
    };

    this.searchDirectory = function(criteria, searchType, onSuccess, onFailure) {
        var type = (searchTypes[searchType] === undefined) ? "-1" : searchTypes[searchType];
        addressbookService.searchDirectory(criteria, type, parseData, onSuccess, onFailure);
    };

};

var addressbookManager = new AddressbookManager();
/**
 * Addressbook and directory.
 *
 * @name addressbook
 * @namespace
 * @memberOf fcs
 * @version 3.0.4
 * @since 3.0.0
 */
var Addressbook = function() {

    /**
     * Addressbook entry.
     *
     * @typedef {Object} AddressbookEntry
     * @readonly
     *
     * @property {?String}  entryId - Unique identifier for the entry.
     * @property {?String}  nickname - Name of the user as it will appear for a personal contact.
     * @property {?String}  primaryContact - User's primary contact number (this should be the prefered number for contacting the user).
     * @property {?String}  firstName - First name of the user.
     * @property {?String}  lastName - Last name of the user.
     * @property {?String}  photoUrl - URL from which to retrieve the picture of the user.
     * @property {?String}  emailAddress - Email address of the user.
     * @property {?String}  homePhone - Home phone number for the user.
     * @property {?String}  mobilePhone - Mobile phone number for the user.
     * @property {?String}  workPhone - Work phone number for the user.
     * @property {!boolean} friendStatus - Friend status of the user.
     * @property {?String}  fax - Fax number of the user.
     * @property {?String}  pager - Pager number of the user.
     *
     */
    this.Entry = addressbookManager.Entry;

    /**
     * Enum for the search criteria filter used in directory searches.
     *
     * @name SearchType
     * @readonly
     * @memberOf fcs.addressbook
     * @enum {number}
     * @since 3.0.0
     *
     * @property {number} FIRSTNAME Search by first name
     * @property {number} LASTNAME Search by last name
     * @property {number} NAME Search by name
     * @property {number} PHONENUMBER Search by phone number
     * @property {number} USERNAME Search by username
     * @property {number} NA Not applicable
     */
    this.SearchType = addressbookManager.SearchType;

    /**
     * Success callback for addressbook retreive/search request.
     *
     * @callback addressbookRequestSuccess
     * @param {Array.<AddressbookEntry>} responseMessage
     */

    /**
     * Failure callback for addressbook retreive/search request.
     *
     * @callback addressbookRequestFailure
     * @param {fcs.Errors} responseCode
     */

    /**
     * Retrieves the list of address book entries from the server
     * and executes the success callback on completion or failure
     * callback on error.
     *
     * @name retrieve
     * @function
     * @since 3.0.0
     * @memberOf fcs.addressbook
     *
     * @param {addressbookRequestSuccess} success callback function
     * @param {addressbookRequestFailure} failure callback function
     *
     * @example
     * var onSuccess = function(entryArray){
     *    var index;
     *    for (index in entryArray) {
     *      console.log(entryArray[index].nickname +", " + entryArray[index].primaryContact);
     *    }
     * };
     *
     * var onError = function (err) {
     *   console.log(err);
     * };
     *
     * fcs.addressbook.retrieve(onSuccess, onError);
     *
     */
    this.retrieve = addressbookManager.retrieve;

    /**
     * Searches the directory.
     *
     * @name searchDirectory
     * @function
     * @since 3.0.0
     * @memberOf fcs.addressbook
     *
     * @param {string} criteria The string to search in the directory
     * @param {fcs.addressbook.SearchType} searchType The criteria (filter) to be applied to the search
     * @param {addressbookRequestSuccess} success callback function
     * @param {addressbookRequestFailure} failure callback function
     *
     * @example
     * var onSuccess = function(entryArray){
     *     var index;
     *     for (index in entryArray) {
     *         console.log(entryArray[index].firstName + ", " + entryArray[index].lastName);
     *     }
     * };
     * var onError = function (err) {
     *   console.log(err);
     * };
     *
     * fcs.addressbook.searchDirectory("Michael", fcs.addressbook.SearchType.FIRSTNAME, onSuccess, onError);
     */
    this.searchDirectory = addressbookManager.searchDirectory;
};

fcs.addressbook = new Addressbook();

var CallTriggerService = function() {
    var logger = logManager.getLogger("callTriggerService");
    this.clickToCall = function(callingParty, calledParty, onSuccess, onFailure) {
        var data = {
            "clickToCallRequest":
            {
                "callingParty": callingParty,
                "calledParty": calledParty
            }
        };
        server.sendPostRequest({
            "url": getWAMUrl(1, "/clicktocall"),
            "data": data
        },
        onSuccess,
        onFailure
        );
    };

    this.getIMRN = function(realm, source, destination, onSuccess, onFailure) {
        logger.info("(Wam Call) getIMRN Function ");

        function parseIMRNResponse(IMRNdata) {
            var receivedIMRN;
            if (IMRNdata && IMRNdata.imrnResponse) {
                receivedIMRN = utils.getProperty(IMRNdata.imrnResponse, 'imrn');
            }
            return receivedIMRN;
        }

        if(destination.match('@')){
         if(destination.split(':')[0]!=="sip"){
            destination = "sip:" + destination;
            }
        }

        var data = {
            "imrnRequest":{
                "realm": realm,
                "sourceAddress": source,
                "destinationAddress": destination
            }
        };
        server.sendPostRequest({
            "url": getWAMUrl(1, "/imrn"),
            "data": data
        },
        onSuccess,
        onFailure,
        parseIMRNResponse
        );
    };

};


var callTriggerService = new CallTriggerService();
var CallTrigger = function() {

    this.clickToCall = callTriggerService.clickToCall;

    this.getIMRN = callTriggerService.getIMRN;

};

fcs.call = new CallTrigger();

/**
* Call related resources (IMRN, Click To Call, Call Disposition).
*
* @name call
* @namespace
* @memberOf fcs
*
* @version 3.0.4
* @since 3.0.0
*/

var Call = function() {

    var videoDeviceStatus = true,notificationState;

   /**
    * This field provides the state of local video status like "recvonly", "sendrecv", "sendrecv" etc.
    *
    * @name fcs.call.localVideoState
    * @field
    * @type {number}
    * @since 3.0.0
    */
    this.localVideoState = 0;

   /**
    * This field provides the state of remote video status like "recvonly", "sendrecv", "sendrecv" etc.
    *
    * @name fcs.call.remoteVideoState
    * @field
    * @since 3.0.0
    * @type {number}
    */
    this.remoteVideoState = 0;

    /**
    * Sets the handler for received call notifications.
    *
    * @name onReceived
    * @event
    * @since 3.0.0
    * @memberOf fcs.call
    * @param {fcs.call.Call} call The call object
    *
    * @example
    * // This function listens received calls
    * function callReceived(call) {
    *    console.log("There is an incomming call...");
    *
    *    //This function listens call state changes in JSL API level
    *    call.onStateChange = function(state) {
    *        onStateChange(call, state);
    *    };
    *
    *    //This function listens media streams in JSL API level
    *    call.onStreamAdded = function(streamURL) {
    *        // Remote Video is turned on by the other end of the call
    *        // Stream URL of Remote Video stream is passed into this function
    *        onStreamAdded(streamURL);
    *    };
    *
    *    // Answering the incomming call
    *    call.answer(onAnswer, onFailure, isVideoAnswer);
    * }
    *
    * fcs.call.onReceived = callReceived;
    */
    this.onReceived = null;

    /**
    * Initialize the media components in order to provide real time communication.
    * When using FCS Plug-in with audio only the plugin will be added as an hidden object to root of the document.
    * When using FCS Plug-in with both audio and video, the object will be added to the videoContainer.
    *
    * @name fcs.call.initMedia
    * @function
    * @since 3.0.0
    * @param {function} [onSuccess] The onSuccess() to be called when the media have been successfully acquired
    * @param {function} [onFailure] The onFailure({@link fcs.call.MediaErrors}) to be called when media could not be aquired
    * @param {object} [options] The options used for initialization
    * @param {string} [options.type="plugin"] The type of media to use (for future use with webRTC)
    * @param {string} [options.pluginLogLevel="2"] The log level of webrtc plugin
    * @param {object} [options.videoContainer] html node in which to inject the video (deprecated)
    * @param {object} [options.removeVideoContainer] html node in which to inject the video
    * @param {object} [options.localVideoContainer] html node in which to inject the preview of the user camera
    * @param {object} [options.iceserver] ice server ip address ex: [{"url" : "stun:206.165.51.23:3478"}]
    * @param {object} [options.pluginMode=LEGACY] use downloaded plugin which disables webrtc capabilities of browser if avaliable
    * @param {object} [options.pluginMode=WEBRTC] use downloaded plugin which overrides webrtc capabilities of browser if avaliable
    * @param {object} [options.pluginMode=AUTO] use webrtc capabilities of browser if avaliable otherwise force user to download plugin
    * @param {object} [options.webrtcdtls=FALSE] webrtc disabled
    * @param {object} [options.webrtcdtls=TRUE] webrtc enabled
    * @param {object} [options.language="en"] language setting of the plugin
    *
    * @example
    * // Media options
    * var mediaOptions = {
    *    "notificationType": "websocket",
    *    "pluginMode": "auto",
    *    "iceserver": [{"url":"stun:206.165.51.69:3478"}],
    *                 [{"url":"turn:206.165.51.69:3478",
    *                   "credential":""}]
    *    "webrtcdtls": false,
    *    "language": "fr"
    * };
    *
    * // Initializing media
    * fcs.call.initMedia(
    *    function() {
    *        console.log("Media was initialized successfully!");
    *    },
    *    function(error) {
    *       switch(error) {
    *            case fcs.call.MediaErrors.WRONG_VERSION : // Alert
    *                console.log("Media Plugin Version Not Supported");
    *                break;
    *
    *            case fcs.call.MediaErrors.NEW_VERSION_WARNING : //Warning
    *                console.log("New Plugin Version is available");
    *                break;
    *
    *            case fcs.call.MediaErrors.NOT_INITIALIZED : // Alert
    *                console.log("Media couldn't be initialized");
    *                break;
    *
    *            case fcs.call.MediaErrors.NOT_FOUND : // Alert
    *                console.log("Plugin couldn't be found!");
    *                break;
    *        }
    *    },
    *    mediaOptions
    * );
    */

    this.initMedia = callManager.initMedia;

    /**
    * Starts a call.
    *
    * @name fcs.call.startCall
    * @function
    * @since 3.0.0
    * @param {string} from The caller's address (e.g. SIP URI) used to establish the call
    * @param {object} [contact] Contains users firstName and lastName
    * @param {string} [contact.firstName="John"] First Name of the user
    * @param {string} [contact.lastName="Doe"] Last Name of the user
    * @param {string} to The callee's address (e.g. SIP URI) used to establish the call
    * @param {function} onSuccess The onSuccess({@link fcs.call.OutgoingCall}) callback function to be called<
    * @param {function} onFailure The onFailure({@link fcs.Errors}) callback function to be called
    * @param {boolean} [isVideoEnabled] This will add m=video to SDP
    * @param {boolean} [sendInitialVideo] In order to make video call set this to true
    * @param {string} [videoQuality] Sets the quality of video
    * @param {string} convID This parameter will only used by smart office clients.
    *
    * @example
    * // Make Voice Call
    * // Start a voice call to the uri indicated with "to" argument
    * // Login is a prerequisite for making calls
    * // contact is an object with two fields contact.firstName and contact.lastName that specifies caller info
    * fcs.call.startCall(fcs.getUser(), contact, to,
    *      function(outgoingCall){
    *                //get callid for your web app to be used later for handling popup windows
    *                var callId = outgoingCall.getId();
    *
    *                outgoingCall.onStateChange = function(state,statusCode){
    *                //Add statusCode that returned from the server property to the call
    *                outgoingCall.statusCode = statusCode;
    *                //Put your web app code to handle call state change like ringing, onCall ...etc.
    *	    };
    *
    *       outgoingCall.onStreamAdded = function(streamURL){
    *           // Setting up source (src tag) of remote video container
    *           $("#remoteVideo").attr("src", streamURL);
    *       };
    *    },
    *    function(){
    *       //put your web app failure handling code
    *       window.alert("CALL_FAILED");
    *    },
    *    false, false);
    *
    */

    this.startCall = callManager.start;

    /**
    * Sets log severity level for Webrtc Plugin (not used for native webrtc)
    * 5 levels(sensitive:0, verbose:1, info:2, warning:3, error:4)
    *
    * @name callManager.set_logSeverityLevel
    * @function
    * @since 3.0.0
    */

    this.set_logSeverityLevel = callManager.set_logSeverityLevel;

    /**
    * Enables log callback for Webrtc Plugin (not used for native webrtc)
    *
    * @name callManager.enable_logCallback
    * @function
    * @since 3.0.0
    */

    this.enable_logCallback = callManager.enable_logCallback;

    /**
    * Disables log callback for Webrtc Plugin (not used for native webrtc)
    *
    * @name callManager.disable_logCallback
    * @function
    * @since 3.0.0
    */

    this.disable_logCallback = callManager.disable_logCallback;

    /**
    * Gets audioInDeviceCount
    *
    * @name fcs.call.get_audioInDeviceCount
    * @function
    * @since 3.0.0
    */

    this.get_audioInDeviceCount = callManager.get_audioInDeviceCount;

    /**
    * Gets audioOutDeviceCount
    *
    * @name fcs.call.get_autioOutDeviceCount
    * @function
    * @since 3.0.0
    */

    this.get_audioOutDeviceCount = callManager.get_audioOutDeviceCount;

    /**
    * Gets videoDeviceCount
    *
    * @name fcs.call.get_videoDeviceCount
    * @function
    * @since 3.0.0
    */

    this.get_videoDeviceCount = callManager.get_videoDeviceCount;

    /**
    * Gets Video Device availability status
    * Only works with PLUGIN
    * @deprecated
    * @name fcs.call.initVideoDeviceStatus
    * @function
    * @since 3.0.0
    */
    this.initVideoDeviceStatus = function() {
        videoDeviceStatus = callManager.hasVideoDevice;
    };

    /**
    * Returns Video Device(Camera) availability
    * @name fcs.call.hasVideoDevice
    * @function
    * @since 3.0.0
    * @example
    * if(fcs.call.hasVideoDevice()){
    *     // If there is a video device available, show local video container
    *     callView.toggleLocalVideo(true);
    * }
    */
    this.hasVideoDevice = callManager.hasVideoDevice;

    /**
    * Returns Audio Device(Microphone) availability
    * @name fcs.call.hasAudioDevice
    * @function
    * @since 3.0.0
    * @example
    * if(!fcs.call.hasAudioDevice()){
    *     window.alert("There is no available audio source!");
    * }
    */
    this.hasAudioDevice = callManager.hasAudioDevice;


    /**
    * Gets User Media functionality for plugin
    * Only works with PLUGIN
    *
    * @name fcs.call.getUserMedia
    * @function
    * @since 3.0.0
    * @example
    * fcs.call.getUserMedia(
    *    function(mediaInfo){
    *        window.console.log("media initialized. mediaInfo: " + JSON.stringify(mediaInfo));
    *    },
    *    function(err){
    *        window.console.log("media initialization error " + err);
    *    },
    *    {
    *        "audio": true,
    *        "video": true,
    *        "audioIndex":0,
    *        "videoIndex":0
    *    }
    * );
    */

    this.getUserMedia = callManager.getUserMedia;

    /**
    * Shows device settings Window
    * Only works with PLUGIN
    *
    * @name fcs.call.showSettingsWindow
    * @function
    * @since 3.0.0
    * @example
    * $("#device_settings_button").click(function() {
    *    fcs.call.showSettingsWindow();
    * });
    */

    this.showSettingsWindow = callManager.showSettingsWindow;

    /**
    * Gets local and remote video resolutions with the order below
    * remoteVideoHeight-remoteVideoWidth
    * Only works with PLUGIN
    *
    * @deprecated
    * @name fcs.call.getVideoResolutions
    * @function
    * @since 3.0.0
    */

    this.getVideoResolutions = callManager.getVideoResolutions;

    /**
    * Gets local video resolutions with the order below
    * localVideoHeight-localVideoWidth
    * Only works with PLUGIN
    *
    * @name fcs.call.getLocalVideoResolutions
    * @function
    * @since 3.0.0
    * @example
    * var pluginLocalVideoResolution = fcs.call.getLocalVideoResolutions();
    * var localVideoHeight = pluginLocalVideoResolution[0];
    * var localVideoWidth = pluginLocalVideoResolution[1];
    * console.log("Local Video Dimensions: " + localVideoWidth + "," + localVideoHeight);
    */

    this.getLocalVideoResolutions = callManager.getLocalVideoResolutions;

    /**
    * Gets remote video resolutions with the order below
    * remoteVideoHeight-remoteVideoWidth
    * Only works with PLUGIN
    *
    * @name fcs.call.getRemoteVideoResolutions
    * @function
    * @since 3.0.0
    * @example
    * var pluginRemoteVideoResolution = fcs.call.getRemoteVideoResolutions();
    * var remoteVideoHeight = pluginRemoteVideoResolution[0];
    * var remoteVideoWidth = pluginRemoteVideoResolution[1];
    * console.log("Remote Video Dimensions: " + remoteVideoWidth + "," + remoteVideoHeight);
    */

    this.getRemoteVideoResolutions = callManager.getRemoteVideoResolutions;

    /**
    * Shows if plugin is enabled.
    * Only works with PLUGIN
    *
    * @name fcs.call.isPluginEnabled
    * @function
    * @since 3.0.0
    * @example
    * if(fcs.call.isPluginEnabled()) {
    *     $("#device_settings_details").show();
    * }
    */

    this.isPluginEnabled = callManager.isPluginEnabled;

    this.hasGotCalls = callManager.hasGotCalls;

    /**
    * Retrived a call by Id.
    *
    * This function allow to retrive a call which was cached by the call continuation feature.
    *
    * @name fcs.call.getIncomingCallById
    * @function
    * @since 3.0.0
    * @param {string} from The id of the incoming call
    * @returns {fcs.call.IncomingCall}
    *
    */
    this.getIncomingCallById = function(id) {
        return callManager.getIncomingCallById(id);
    };

    /**
    * Create a renderer for an audio/video stream
    *
    * @name fcs.call.createStreamRenderer
    * @function
    * @since 3.0.0
    * @param {string} streamUrl The url of the stream
    * @param {object} container The DOM node into which to create the renderer (the content of the node will be cleared)
    * @param {object} options The options to be used for the renderer
    * @returns {Object} renderer Renderer object
    *
    */
    this.createStreamRenderer = callManager.createStreamRenderer;

    /**
    * Discpose of a previously created renderer
    *
    * @name fcs.call.disposeStreamRenderer
    * @function
    * @since 3.0.0
    * @param {object} container The DOM node into which the renderer was previously created
    */
    this.disposeStreamRenderer = callManager.disposeStreamRenderer;

    /**
    * States of the Call.
    * @name States
    * @enum {number}
    * @since 3.0.0
    * @readonly
    * @memberOf fcs.call
    * @property {number} [IN_CALL=0] The call has been established.
    * @property {number} [ON_HOLD=1] The call has been put on hold.
    * @property {number} [RINGING=2] The outgoing call is ringing.
    * @property {number} [ENDED=3] The call has been terminated.
    * @property {number} [REJECTED=4] The outgoing call request has been rejected by the other party.
    * @property {number} [OUTGOING=5] The outgoing call request has been sent but no response have been received yet.
    * @property {number} [INCOMING=6] The incoming call has been received but has not been answered yet.
    * @property {number} [ANSWERING=7] The incoming call has been answered but the call as not been establish yet.
    * @property {number} [JOINED=8] The call is joined.
    * @property {number} [RENEGOTIATION=9] The call is re-established.
    * @property {number} [TRANSFERRED=10] The call is treansffered to a third party
    * @property {number} [ON_REMOTE_HOLD=11] The call has been put on hold remotely.
    */
    this.States = callManager.CALL_STATES;

    /**
    * Hold states of the Call.
    * @name HoldStates
    * @enum {number}
    * @since 3.0.0
    * @readonly
    * @memberOf fcs.call
    * @property {number} [LOCAL_HOLD=0] The call has been put on hold locally.
    * @property {number} [REMOTE_HOLD=1] The call has been put on hold remotely.
    * @property {number} [BOTH_HOLD=2] he call has been put on both locally and remotely.
    */
    this.HoldStates = callManager.CALL_HOLD_STATES;

    /**
    * Type of media initialization errors.
    * @name MediaErrors
    * @enum {number}
    * @since 3.0.0
    * @readonly
    * @memberOf fcs.call
    * @property {number} [NOT_FOUND=1] No media source available.
    * @property {number} [NOT_ALLOWED=2] User did not allow media use.
    * @property {number} [OPTIONS=3] Missing or wrong use of options.
    * @property {number} [WRONG_VERSION=4] The version of the plugin is not supported.
    * @property {number} [NOT_INITIALIZED=5] The media is not initialized.
    * @property {number} [NEW_VERSION_WARNING=6] New plugin version is available.
    */
    this.MediaErrors = {

        NOT_FOUND: 1,

        NOT_ALLOWED: 2,

        OPTIONS: 3,

        WRONG_VERSION: 4,

        NOT_INITIALIZED: 5,

        NEW_VERSION_WARNING: 6
    };

    /**
    * Call a party through a client device using the Click To Call service.
    *
    * @name fcs.call.clickToCall
    * @function
    * @since 3.0.0
    * @param {string} callingParty The caller's address (e.g. SIP) used to establish the call
    * @param {string} calledParty The callee's address (e.g. SIP) used to establish the call
    * @param {function} onSuccess The onSuccess() callback to be called
    * @param {function} onFailure The onFailure({@link fcs.Errors}) callback to be called
    *
    * @example
    * var onSuccess = function(){
    *    //do something here
    * };
    * var onError = function (err) {
    *   //do something here
    * };
    *
    * fcs.call.clickToCall("user1@test.com", "user2@test.com", onSuccess, onError);
    */

   /**
    * Provide the user with a routable PSTN number as a result of an IMRN allocation request.
    *
    * @name fcs.call.getIMRN
    * @function
    * @param {string} realm The pool of numbers from which IMRN will be allocated
    * @param {string} source The URI of the individual placing the call
    * @param {string} destination The URI of the individual receiving the call
    * @param {function} onSuccess The onSuccess() callback to be called
    * @param {function} onFailure The onFailure({@link fcs.Errors}) callback to be called
    */

    /**
     * Call is super class of {@link fcs.call.IncomingCall} and {@link fcs.call.OutgoingCall}
     *
     * @name Call
     * @class
     * @since 3.0.0
     * @memberOf fcs.call
     * @param {String} callid Unique identifier for the call
     * @version 3.0.4
     * @since 3.0.0
     */
    this.Call = function(callid){};

    /**
    * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
    *
    * @name IncomingCall
    * @class
    * @since 3.0.0
    * @memberOf fcs.call
    * @augments fcs.call.Call
    * @param {String} callid Unique identifier for the call
    * @param {Object} data options
    * @param {Boolean} data.reject can reject. This is a call disposition option.
    * @param {Boolean} data.forward can forward. This is a call disposition option.
    * @param {Boolean} data.answer can answer. This is a call disposition option.
    * @version 3.0.4
    * @since 3.0.0
    */
    this.IncomingCall = function(callid, data){
        var id = callid, options = data, self = this, sendVideo = true, receiveVideo = true, receivingVideo = false, isJoin = false, onJoin, buttonDisabler = false, btnTimeout,
        auditTimer, isHold = false, holdState = null;

        this.notificationQueue = new utils.Queue();

        /**
         * Sets the handler for listening local video stream ready event.
         *
         * @name fcs.call.IncomingCall#onLocalStreamAdded
         * @function
         * @since 3.0.0.1
         *
         **/
        this.onLocalStreamAdded = null;

        /**
         * Sets the handler for listening remote video stream ready event.
         *
         * @name fcs.call.IncomingCall#onStreamAdded
         *
         * @function
         * @since 2.0.0
         * @param {?String} streamUrl remote video streamUrl
         *
         **/
        this.onStreamAdded = null;

        /**
       * @name fcs.call.IncomingCall#calleeNumber
       * @field
       * @since 3.0.0
       * @type {String}
       *
       * @example
       *
       * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
       *
       * var incomingCall = {};
       * fcs.call.onReceived = function(call) {
       *    incomingCall = call;
       * };
       *
       * incomingCall.calleeNumber;
       */

        /**
       * @name fcs.call.IncomingCall#callerNumber
       * @field
       * @since 3.0.0
       * @type {String}
       *
       * @example
       *
       * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
       *
       * var incomingCall = {};
       * fcs.call.onReceived = function(call) {
       *    incomingCall = call;
       * };
       *
       * incomingCall.callerNumber;
       */

        /**
       * @name fcs.call.IncomingCall#callerName
       * @field
       * @since 3.0.0
       * @type {String}
       *
       * @example
       *
       * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
       *
       * var incomingCall = {};
       * fcs.call.onReceived = function(call) {
       *    incomingCall = call;
       * };
       *
       * incomingCall.callerName;
       */

        /**
       * @name fcs.call.IncomingCall#primaryContact
       * @field
       * @since 3.0.0
       * @type {String}
       *
       * @example
       *
       * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
       *
       * var incomingCall = {};
       * fcs.call.onReceived = function(call) {
       *    incomingCall = call;
       * };
       *
       * incomingCall.primaryContact;
       */


        /**
         * Puts the speaker into mute.
         *
         * @name fcs.call.IncomingCall#mute
         * @function
         * @since 3.0.0
         *
         * @example
         *
         * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
         *
         * var incomingCall = {};
         * fcs.call.onReceived = function(call) {
         *    incomingCall = call;
         * };
         *
         * incomingCall.mute();
         */
        this.mute = function(){
            callManager.mute(id, true);
        };

        /**
         * Puts the speaker into unmute.
         *
         * @name fcs.call.IncomingCall#unmute
         * @function
         * @since 3.0.0
         *
         * @example
         *
         * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
         *
         * var incomingCall = {};
         * fcs.call.onReceived = function(call) {
         *    incomingCall = call;
         * };
         *
         * incomingCall.unmute();
         */
        this.unmute = function(){
            callManager.mute(id, false);
        };

        /**
         * Answers the call.
         * @name fcs.call.IncomingCall#answer
         * @function
         * @since 3.0.0
         * @param {function} onSuccess The onSuccess() callback function to be called
         * @param {function} onFailure The onFailure({@link fcs.Errors}) callback function to be called
         * @param {boolean} [isVideoEnabled] Start call with video or not
         * @param {String} [videoQuality] Video quality
         *
         * @example
         *
         * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
         *
         * var incomingCall = {};
         * fcs.call.onReceived = function(call) {
         *    incomingCall = call;
         * };
         *
         * var onSuccess = function(){
         *    //do something here
         * };
         * var onError = function (err) {
         *   //do something here
         * };
         *
         * incomingCall.answer(onSuccess, onFailure, true, "1280x720");
         */
        this.answer = function(onSuccess, onFailure, isVideoEnabled, videoQuality){
            if(options.answer){
                callManager.answer(id, onSuccess, onFailure, isVideoEnabled, videoQuality);
            } else {
                onFailure();
            }
        };

        /**
         * Rejects the call
         *
         * @name fcs.call.IncomingCall#reject
         * @function
         * @since 3.0.0
         * @param {function} onSuccess The onSuccess() callback function to be called
         * @param {function} onFailure The onFailure({@link fcs.Errors}) callback function to be called
         *
         * @example
         *
         * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
         *
         * var incomingCall = {};
         * fcs.call.onReceived = function(call) {
         *    incomingCall = call;
         * };
         *
         * var onSuccess = function(){
         *    //do something here
         * };
         * var onError = function (err) {
         *   //do something here
         * };
         *
         * incomingCall.reject(onSuccess, onFailure);
         */
        this.reject = function(onSuccess, onFailure) {
            if(options.reject){
                callManager.reject(id, onSuccess, onFailure);
            } else {
                onFailure();
            }
        };

        /**
         * Ignores the call. Client will not send any rest request for this one. Ignore is on client side only.
         *
         * @name fcs.call.IncomingCall#ignore
         * @function
         * @since 3.0.0
         * @param {function} onSuccess The onSuccess() callback function to be called
         * @param {function} onFailure The onFailure({@link fcs.Errors}) callback function to be called
         *
         * @example
         *
         * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
         *
         * var incomingCall = {};
         * fcs.call.onReceived = function(call) {
         *    incomingCall = call;
         * };
         *
         * var onSuccess = function(){
         *    //do something here
         * };
         * var onError = function (err) {
         *   //do something here
         * };
         *
         * incomingCall.ignore(onSuccess, onFailure);
         */
        this.ignore = function(onSuccess, onFailure) {
            callManager.ignore(id, onSuccess, onFailure);
        };

        /**
         * Forwards the call.
         *
         * @name fcs.call.IncomingCall#forward
         * @function
         * @since 3.0.0
         * @param {string} address The address where the call is transferred (e.g. SIP URI)
         * @param {function} onSuccess The onSuccess() callback function to be called
         * @param {function} onFailure The onFailure({@link fcs.Errors}) callback function to be called
         *
         * @example
         *
         * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
         *
         * var incomingCall = {};
         * fcs.call.onReceived = function(call) {
         *    incomingCall = call;
         * };
         *
         * var onSuccess = function(){
         *    //do something here
         * };
         * var onError = function (err) {
         *   //do something here
         * };
         *
         * incomingCall.forward("user1@test.com", onSuccess, onFailure);
         */
        this.forward = function(address, onSuccess, onFailure) {
            if(options.forward){
                callManager.forward(id, address, onSuccess, onFailure);
            } else {
                onFailure();
            }
        };

        /**
         *
         * Checks the incoming call if it has reject option.
         *
         * @name fcs.call.IncomingCall#canReject
         * @function
         * @since 3.0.0
         * @returns {Boolean}
         *
         * @example
         *
         * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
         *
         * var incomingCall = {};
         * fcs.call.onReceived = function(call) {
         *    incomingCall = call;
         * };
         *
         * incomingCall.canReject();
         */
        this.canReject = function(){
            return options.reject === true;
        };

        /**
         *
         * Checks the incoming call if it has forward option.
         *
         * @name fcs.call.IncomingCall#canForward
         * @function
         * @since 3.0.0
         * @returns {Boolean}
         *
         * @example
         *
         * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
         *
         * var incomingCall = {};
         * fcs.call.onReceived = function(call) {
         *    incomingCall = call;
         * };
         *
         * incomingCall.canForward();
         */
        this.canForward = function(){
            return options.forward === true;
        };

        /**
         * Checks the incoming call if it has answer option.
         *
         * @name fcs.call.IncomingCall#canAnswer
         * @function
         * @since 3.0.0
         * @returns {Boolean}
         *
         * @example
         *
         * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
         *
         * var incomingCall = {};
         * fcs.call.onReceived = function(call) {
         *    incomingCall = call;
         * };
         *
         * incomingCall.canAnswer();
         */
        this.canAnswer = function(){
            return options.answer === true;
        };

        /**
         * Are we able to send video.
         * Ex: Client may try to send video but video cam can be unplugged. Returns false in that case
         *
         * @name fcs.call.IncomingCall#canSendVideo
         * @function
         * @since 3.0.0
         * @returns {Boolean}
         *
         * @example
         *
         * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
         *
         * var incomingCall = {};
         * fcs.call.onReceived = function(call) {
         *    incomingCall = call;
         * };
         *
         * incomingCall.canSendVideo();
         */
        this.canSendVideo = function(){
            return sendVideo;
        };

        /**
         * Are we able to send video. Checks the incoming SDP
         *
         * @name fcs.call.IncomingCall#canReceiveVideo
         * @function
         * @since 3.0.0
         * @returns {Boolean}
         *
         * @example
         *
         * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
         *
         * var incomingCall = {};
         * fcs.call.onReceived = function(call) {
         *    incomingCall = call;
         * };
         *
         * incomingCall.canReceiveVideo();
         */
        this.canReceiveVideo = function(){
            return receiveVideo;
        };

        /**
         * Are we able to receive video. Checks the incoming SDP
         *
         * @name fcs.call.IncomingCall#canReceivingVideo
         * @function
         * @since 3.0.0
         * @returns {Boolean}
         *
         * @example
         *
         * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
         *
         * var incomingCall = {};
         * fcs.call.onReceived = function(call) {
         *    incomingCall = call;
         * };
         *
         * incomingCall.canReceivingVideo();
         */
        this.canReceivingVideo = function(){
            return receivingVideo;
        };

        /**
         * sets the outgoing video condition.
         *
         * @name fcs.call.IncomingCall#setSendVideo
         * @function
         * @since 3.0.0
         * @param {Boolean} videoSendStatus video send status
         *
         * @example
         *
         * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
         *
         * var incomingCall = {};
         * fcs.call.onReceived = function(call) {
         *    incomingCall = call;
         * };
         *
         * incomingCall.setSendVideo(true);
         */
        this.setSendVideo = function(videoSendStatus){
            sendVideo = videoDeviceStatus && videoSendStatus;
        };

        /**
         * sets the outgoing video condition
         *
         * @name fcs.call.IncomingCall#setReceiveVideo
         * @function
         * @since 3.0.0
         * @param {Boolean} videoReceiveStatus video receive status
         *
         * @example
         *
         * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
         *
         * var incomingCall = {};
         * fcs.call.onReceived = function(call) {
         *    incomingCall = call;
         * };
         *
         * incomingCall.setReceiveVideo(true);
         */
        this.setReceiveVideo = function(videoReceiveStatus){
            receiveVideo = videoReceiveStatus;
        };

        /**
         * sets the incoming video condition
         *
         * @name fcs.call.IncomingCall#setReceivingVideo
         * @function
         * @since 3.0.0
         * @param {Boolean} isReceiving video receive status
         *
         * @example
         *
         * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
         *
         * var incomingCall = {};
         * fcs.call.onReceived = function(call) {
         *    incomingCall = call;
         * };
         *
         * incomingCall.setReceivingVideo(true);
         */
        this.setReceivingVideo = function(isReceiving){
            receivingVideo = isReceiving;
        };

        /**
         * @deprecated Do not use this function, it will be removed on 3.0.5
         *
         * @name fcs.call.IncomingCall#setHold
         * @function
         * @since 3.0.0
         */
        this.setHold = function(hold) {
            isHold = hold;
        };

        /**
         * @deprecated Do not use this function, use call.getHoldState()
         *
         * @name fcs.call.IncomingCall#getHold
         * @function
         * @since 3.0.0
         */
        this.getHold = function() {
            return isHold;
        };

        /**
         * @deprecated Do not use this function,  it will be removed on 3.0.5
         *
         * @name fcs.call.IncomingCall#setHoldState
         * @function
         * @since 3.0.0
         */
        this.setHoldState = function(s) {
            holdState = s;
        };

         /**
         * Returns hold state of call.
         *
         * @name fcs.call.IncomingCall#getHoldState
         * @function
         * @since 3.0.4
         * @returns {@link fcs.HoldStates} or undefined if call has not been put
         * on hold.
         *
         * @example
         *
         * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
         *
         * var incomingCall = {};
         * fcs.call.onReceived = function(call) {
         *    incomingCall = call;
         * };
         *
         * incomingCall.getHoldState();
         */
        this.getHoldState = function() {
            return callManager.getHoldStateOfCall(id);
        };

        /**
         * Gets call id.
         *
         * @name fcs.call.IncomingCall#getId
         * @function
         * @since 3.0.0
         * @returns {id} Unique identifier for the call
         *
         * @example
         *
         * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
         *
         * var incomingCall = {};
         * fcs.call.onReceived = function(call) {
         *    incomingCall = call;
         * };
         *
         * incomingCall.getId();
         */
        this.getId = function(){
            return id;
        };

        /**
         * End the call
         *
         * @name fcs.call.IncomingCall#end
         * @function
         * @since 3.0.0
         * @param {function} onSuccess The onSuccess() callback function to be called
         *
         * @example
         *
         * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
         *
         * var incomingCall = {};
         * fcs.call.onReceived = function(call) {
         *    incomingCall = call;
         * };
         *
         * var onSuccess = function(){
         *    //do something here
         * };
         *
         * incomingCall.end(onSuccess);
         */
        this.end = function(onSuccess){
            callManager.end(id, onSuccess);
        };

        /**
          * Holds the call.
          *
          * @name fcs.call.IncomingCall#hold
          * @function
          * @since 3.0.0
          * @param {function} onSuccess The onSuccess() callback function to be called
          * @param {function} onFailure The onFailure({@link fcs.Errors}) callback function to be called
          *
          * @example
          *
          * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
          *
          * var incomingCall = {};
          * fcs.call.onReceived = function(call) {
          *    incomingCall = call;
          * };
          *
          * var onSuccess = function(){
          *    //do something here
          * };
          * var onFailure = function(err){
          *    //do something here
          * };
          *
          * incomingCall.hold(onSuccess, onFailure);
          */
        this.hold = function(onSuccess, onFailure){
            callManager.hold(callid, onSuccess, onFailure);
        };

        /**
         * Resume the call.
         *
         * @name fcs.call.IncomingCall#unhold
         * @function
         * @since 3.0.0
         * @param {function} onSuccess The onSuccess() callback function to be called
         * @param {function} onFailure The onFailure({@link fcs.Errors}) callback function to be called
         *
         * @example
         *
         * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
         *
         * var incomingCall = {};
         * fcs.call.onReceived = function(call) {
         *    incomingCall = call;
         * };
         *
         * var onSuccess = function(){
         *    //do something here
         * };
         * var onFailure = function(err){
         *    //do something here
         * };
         *
         * incomingCall.unhold(onSuccess, onFailure);
         */
        this.unhold = function(onSuccess,onFailure){
            callManager.unhold(id, onSuccess,onFailure);
        };

        this.directTransfer = function(address,onSuccess,onFailure){
            callManager.directTransfer(id, address, onSuccess,onFailure);
        };

        /**
         * Stop the video for this call after the call is established
         *
         * @name fcs.call.IncomingCall#videoStop
         * @function
         * @since 3.0.0
         * @param {function} onSuccess The onSuccess() callback function to be called
         * @param {function} onFailure The onFailure({@link fcs.Errors}) callback function to be called
         *
         * @example
         *
         * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
         *
         * var incomingCall = {};
         * fcs.call.onReceived = function(call) {
         *    incomingCall = call;
         * };
         *
         * var onSuccess = function(){
         *    //do something here
         * };
         * var onFailure = function(err){
         *    //do something here
         * };
         *
         * incomingCall.videoStop(onSuccess, onFailure);
         */
        this.videoStop = function(onSuccess, onFailure){
            callManager.videoStopStart(callid, onSuccess, onFailure, false);
        };

        /**
         * Start the video for this call after the call is established
         *
         * @name fcs.call.IncomingCall#videoStart
         * @function
         * @since 3.0.0
         * @param {function} onSuccess The onSuccess() callback function to be called
         * @param {function} onFailure The onFailure() callback function to be called
         * @param {string} [videoQuality] Sets the quality of video, this parameter will be passed to getUserMedia()
         *                  if the video source is allowed before, this parameter will not be used
         *
         * @example
         *
         * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
         *
         * var incomingCall = {};
         * fcs.call.onReceived = function(call) {
         *    incomingCall = call;
         * };
         *
         * var onSuccess = function(){
         *    //do something here
         * };
         * var onFailure = function(err){
         *    //do something here
         * };
         *
         * incomingCall.videoStart(onSuccess, onFailure);
         */
        this.videoStart = function(onSuccess, onFailure, videoQuality){
            callManager.videoStopStart(callid, onSuccess, onFailure, true, videoQuality);
        };

        /**
         * Join 2 calls
         * You need two different calls to establish this functionality.
         * In order to join two calls. both calls must be put in to hold state first.
         * If not call servers will not your request.
         *
         * @name fcs.call.IncomingCall#join
         * @function
         * @since 3.0.0
         * @param {fcs.call.Call} anotherCall Call that we want the current call to be joined to.
         * @param {function} onSuccess The onSuccess({@link fcs.call.Call}) to be called when the call have been joined provide the joined call as parameter
         * @param {function} [onFailure] The onFailure() to be called when media could not be join
         *
         * @example
         *
         * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
         *
         * var incomingCall = {};
         * fcs.call.onReceived = function(call) {
         *    incomingCall = call;
         * };
         *
         * And another {@link fcs.call.OutgoingCall} or {@link fcs.call.IncomingCall} is requeired which is going to be joined.
         * var anotherCall; // assume this is previosuly created.
         *
         * var joinOnSuccess = function(joinedCall){
         *    joinedCall // newly created.
         *    //do something here
         * };
         * var joinOnFailure = function(){
         *    //do something here
         * };
         *
         * incomingCall.join(anotherCall, joinOnSuccess, joinOnFailure);
         *
         * When join() is successfuly compeled, joinOnSuccess({@link fcs.call.OutgoingCall}) will be invoked.
         */
        this.join = function(anotherCall, onSuccess, onFailure){
            callManager.join(id, anotherCall.getId(), onSuccess, onFailure);
        };

        /**
         * Send Dual-tone multi-frequency signaling.
         *
         * @name fcs.call.IncomingCall#sendDTMF
         * @function
         * @since 3.0.0
         * @param {String} tone Tone to be send as dtmf.
         *
         * @example
         *
         * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
         *
         * var incomingCall = {};
         * fcs.call.onReceived = function(call) {
         *    incomingCall = call;
         * };
         *
         * incomingCall.sendDTMF("0");
         */
        this.sendDTMF = function(tone){
            callManager.sendDTMF(id, tone);
        };

        /**
         * Force the plugin to send a IntraFrame
         * Only used by PLUGIN.
         * This needs to be called when sending video.
         * Solves video freeze issue
         *
         * @name fcs.call.IncomingCall#sendIntraFrame
         * @function
         * @since 3.0.0
         *
         * @example
         *
         * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
         *
         * var incomingCall = {};
         * fcs.call.onReceived = function(call) {
         *    incomingCall = call;
         * };
         *
         * incomingCall.sendIntraFrame();
         */
        this.sendIntraFrame = function(){
            if (sendVideo) {
                callManager.sendIntraFrame(id);
            }
        };

        /**
         * Force the plugin to send a BlackFrame
         * Only used by PLUGIN.
         * Some of the SBC's(Session Border Controllers) do not establish one way video.
         * audio only side has to send a blackFrame in order to see the incoming video
         *
         * @name fcs.call.IncomingCall#sendBlackFrame
         * @function
         * @since 3.0.0
         *
         * @example
         *
         * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
         *
         * var incomingCall = {};
         * fcs.call.onReceived = function(call) {
         *    incomingCall = call;
         * };
         *
         * incomingCall.sendBlackFrame();
         */
        this.sendBlackFrame = function(){
            callManager.sendBlackFrame(id);
        };

        /**
         * Force the plugin to refresh video renderer
         * with this call's remote video stream
         * Only used by PLUGIN.
         *
         * @name fcs.call.IncomingCall#refreshVideoRenderer
         * @function
         * @since 3.0.0
         *
         * @example
         *
         * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
         *
         * var incomingCall = {};
         * fcs.call.onReceived = function(call) {
         *    incomingCall = call;
         * };
         *
         * incomingCall.refreshVideoRenderer();
         */
        this.refreshVideoRenderer = function(){
            callManager.refreshVideoRenderer(id);
        };

        /**
         * Returns the call is a join call or not
         * Do not use this function if you really dont need it.
         * This will be handled by the framework
         *
         * @name fcs.call.IncomingCall#getJoin
         * @function
         * @since 3.0.0
         * @returns {Boolean} isJoin
         *
         * @example
         *
         * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
         *
         * var incomingCall = {};
         * fcs.call.onReceived = function(call) {
         *    incomingCall = call;
         * };
         *
         * incomingCall.getJoin();
         */
        this.getJoin = function() {
            return isJoin;
        };

        /**
         * Marks the call as a join call or not
         * Do not use this function if you really dont need it.
         * This will be handled by the framework
         *
         * @name fcs.call.IncomingCall#setJoin
         * @function
         * @since 3.0.0
         * @param {String} join
         *
         * @example
         *
         * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
         *
         * var incomingCall = {};
         * fcs.call.onReceived = function(call) {
         *    incomingCall = call;
         * };
         *
         * incomingCall.setJoin(true);
         */
        this.setJoin = function (join) {
            isJoin = join;
        };

        /**
         * Returns the button is a disabled or not
         * You may want to disable your buttons while waiting for a response.
         * Ex: this will prevent clicking multiple times for hold button until first hold response is not recieved
         *
         * @name fcs.call.IncomingCall#getButtonDisabler
         * @function
         * @since 3.0.0
         * @returns {Boolean} buttonDisabler
         *
         * @example
         *
         * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
         *
         * var incomingCall = {};
         * fcs.call.onReceived = function(call) {
         *    incomingCall = call;
         * };
         *
         * incomingCall.getButtonDisabler();
         */
        this.getButtonDisabler = function() {
            return buttonDisabler;
        };

        /**
         * Disable the button after waiting 4000 milliseconds.
         * You may want to disable your buttons while waiting for a response.
         * Ex: this will prevent clicking multiple times for hold button until first hold response is not recieved
         *
         * @name fcs.call.IncomingCall#setButtonDisabler
         * @function
         * @since 3.0.0
         * @param {Boolean} disable
         *
         * @example
         *
         * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
         *
         * var incomingCall = {};
         * fcs.call.onReceived = function(call) {
         *    incomingCall = call;
         * };
         *
         * incomingCall.setButtonDisabler(true);
         */
        this.setButtonDisabler = function(disable) {
            buttonDisabler = disable;
            if(buttonDisabler) {
                btnTimeout = setTimeout( function() {
                    buttonDisabler = false;
                },
                4000 );
            }
        };

        /**
         * Clears the timer set with fcs.call.IncomingCall#setButtonDisabler.
         * You may want to disable your buttons while waiting for a response.
         * Ex: this will prevent clicking multiple times for hold button until first hold response is not recieved
         *
         * @name fcs.call.IncomingCall#clearBtnTimeout
         * @function
         * @since 3.0.0
         *
         * @example
         *
         * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
         *
         * var incomingCall = {};
         * fcs.call.onReceived = function(call) {
         *    incomingCall = call;
         * };
         *
         * incomingCall.clearBtnTimeout();
         */
        this.clearBtnTimeout = function() {
            clearTimeout(btnTimeout);
        };


        /**
        * Long call audit
        * Creates a timer after call is established.
        * This timer sends a "PUT" request to server.
        * This will continue until one request fails.
        * Handled by framework. You dont need to call this function
        *
        * @name fcs.call.IncomingCall#setAuditTimer
        * @function
        * @since 3.0.0
        *
        * @example
        *
        * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
        * incomingCall.setAuditTimer(audit);
        */
        this.setAuditTimer = function (audit) {
            auditTimer = setInterval(function() {
                audit();
            },
            fcsConfig.callAuditTimer ? fcsConfig.callAuditTimer:30000);
        };


        /**
        * Clears the long call audit prior to clearing all call resources.
        * Handled by framework. you dont need to call this function
        *
        * @name fcs.call.IncomingCall#clearAuditTimer
        * @function
        * @since 3.0.0
        *
        * @example
        *
        * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
        */
        this.clearAuditTimer = function() {
            clearInterval(auditTimer);
        };

        this.isCallMuted = function(id) {
            return callManager.isCallMuted(id);
        };

        /**
         * Returns video negotation availability
         * @name fcs.call.IncomingCall#isVideoNegotationAvailable
         * @function
         * @since 3.0.1
         * @example
         * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
         *
         * var incomingCall = {};
         * fcs.call.onReceived = function(call) {
         *    incomingCall = call;
         * };
         *
         * incomingCall.isVideoNegotationAvailable();
         */
        this.isVideoNegotationAvailable = function(id) {
            return callManager.isVideoNegotationAvailable(id);
        };

        /**
         * Returns the state of the remote video.
         * @name fcs.call.IncomingCall#getRemoteVideoState
         * @function
         * @since 3.0.6
         */
        this.getRemoteVideoState = function() {
            return callManager.getRemoteVideoState(this.getId());
        };
    };

    this.IncomingCall.prototype = new this.Call();

    /**
    * @name OutgoingCall
    * @class
    * @memberOf fcs.call
    * @augments fcs.call.Call
    * @param {String} callid Unique identifier for the call
    * @version 3.0.4
    * @since 3.0.0
    */
    this.OutgoingCall = function(callid){
        var id = callid, self = this, sendVideo = true, receiveVideo = true, receivingVideo = false, isJoin = false, onJoin, buttonDisabler = false, btnTimeout,
        auditTimer, isHold = false, holdState = null;

        this.notificationQueue = new utils.Queue();

        /**
         * Sets the handler for listening local video stream ready event.
         *
         * @name fcs.call.OutgoingCall#onLocalStreamAdded
         * @function
         * @since 3.0.0.1
         *
         **/
        this.onLocalStreamAdded = null;

        /**
         * Sets the handler for listening remote video stream ready event.
         *
         * @name fcs.call.OutgoingCall#onStreamAdded
         *
         * @function
         * @since 2.0.0
         * @param {?String} streamUrl remote video streamUrl
         *
         **/
        this.onStreamAdded = null;

        /**
         * Are we able to send video.
         * Ex: Client may try to send video but video cam can be unplugged. Returns false in that case
         *
         * @name fcs.call.OutgoingCall#canSendVideo
         * @function
         * @since 3.0.0
         * @returns {Boolean}
         *
         * @example
         *
         * A previously created {@link fcs.call.OutgoingCall} is required. {@see {@link fcs.call.startCall}} for more details.
         *
         * var outgoingCall = {};
         * fcs.call.startCall(..., ..., ..., onSuccess(outgoingCall), ..., ...);
         * outgoingCall.canSend();
         */
        this.canSendVideo = function(){
            return sendVideo;
        };

        /**
         * Are we able to send video. Checks the incoming SDP
         *
         * @name fcs.call.OutgoingCall#canReceiveVideo
         * @function
         * @since 3.0.0
         * @returns {Boolean}
         *
         * @example
         *
         * A previously created {@link fcs.call.OutgoingCall} is required. {@see {@link fcs.call.startCall}} for more details.
         *
         * var outgoingCall = {};
         * fcs.call.startCall(..., ..., ..., onSuccess(outgoingCall), ..., ...);
         * outgoingCall.canReceiveVideo();
         */
        this.canReceiveVideo = function(){
            return receiveVideo;
        };

        /**
         * Are we able to receive video. Checks the incoming SDP
         *
         * @name fcs.call.OutgoingCall#canReceivingVideo
         * @function
         * @since 3.0.0
         * @returns {Boolean}
         *
         * @example
         *
         * A previously created {@link fcs.call.OutgoingCall} is required. {@see {@link fcs.call.startCall}} for more details.
         *
         * var outgoingCall = {};
         * fcs.call.startCall(..., ..., ..., onSuccess(outgoingCall), ..., ...);
         * outgoingCall.canReceivingVideo();
         */
        this.canReceivingVideo = function(){
            return receivingVideo;
        };

        /**
         * sets the outgoing video condition.
         *
         *
         * @name fcs.call.OutgoingCall#setSendVideo
         * @function
         * @since 3.0.0
         * @param {Boolean} videoSendStatus video send status
         *
         * @example
         *
         * A previously created {@link fcs.call.OutgoingCall} is required. {@see {@link fcs.call.startCall}} for more details.
         *
         * var outgoingCall = {};
         * fcs.call.startCall(..., ..., ..., onSuccess(outgoingCall), ..., ...);
         * outgoingCall.setSendVideo(true);
         */
        this.setSendVideo = function(videoSendStatus){
            sendVideo = videoDeviceStatus && videoSendStatus;
        };

        /**
         * sets the outgoing video condition
         *
         * @name fcs.call.OutgoingCall#setReceiveVideo
         * @function
         * @since 3.0.0
         * @param {Boolean} videoReceiveStatus video receive status
         *
         * @example
         *
         * A previously created {@link fcs.call.OutgoingCall} is required. {@see {@link fcs.call.startCall}} for more details.
         *
         * var outgoingCall = {};
         * fcs.call.startCall(..., ..., ..., onSuccess(outgoingCall), onFail(error), ...);
         * outgoingCall.setReceiveVideo(true);
         */
        this.setReceiveVideo = function(videoReceiveStatus){
            receiveVideo = videoReceiveStatus;
        };

        /**
         * sets the incoming video condition
         *
         * @name fcs.call.OutgoingCall#setReceivingVideo
         * @function
         * @since 3.0.0
         * @param {Boolean} isReceiving video receive status
         *
         * @example
         *
         * A previously created {@link fcs.call.OutgoingCall} is required. {@see {@link fcs.call.startCall}} for more details.
         *
         * var outgoingCall = {};
         * fcs.call.startCall(..., ..., ..., onSuccess(outgoingCall), ..., ...);
         * outgoingCall.isReceiving(true);
         */
        this.setReceivingVideo = function(isReceiving){
            receivingVideo = isReceiving;
        };

        /**
         * @deprecated Do not use this function, it will be removed on 3.0.5
         *
         * @name fcs.call.OutgoingCall#setHold
         * @function
         * @since 3.0.0
         */
        this.setHold = function(hold) {
            isHold = hold;
        };

        /**
         * @deprecated Do not use this function, use call.getHoldState()
         *
         * @name fcs.call.OutgoingCall#getHold
         * @function
         * @since 3.0.0
         */
        this.getHold = function() {
            return isHold;
        };

        /**
         * @deprecated Do not use this function,  it will be removed on 3.0.5
         *
         * @name fcs.call.OutgoingCall#setHoldState
         * @function
         * @since 3.0.0
         */
        this.setHoldState = function(s) {
            holdState = s;
        };

         /**
         * Returns hold state of call.
         *
         * @name fcs.call.OutgoingCall#getHoldState
         * @function
         * @since 3.0.4
         * @returns {@link fcs.HoldStates} or undefined if call has not been put
         * on hold.
         *
         * @example
         *
         * When an outgoingCall call is received, {@link fcs.call.event:onReceived} handler will be invoked.
         *
         * var outgoingCall = {};
         * fcs.call.startCall(..., ..., ..., onSuccess(outgoingCall), ..., ...);
         *
         * outgoingCall.getHoldState();
         */
        this.getHoldState = function() {
            return callManager.getHoldStateOfCall(id);
        };

        /**
         * Gets call id.
         *
         * @name fcs.call.OutgoingCall#getId
         * @function
         * @since 3.0.0
         * @returns {id} Unique identifier for the call
         *
         * @example
         *
         * A previously created {@link fcs.call.OutgoingCall} is required. {@see {@link fcs.call.startCall}} for more details.
         *
         * var outgoingCall = {};
         * fcs.call.startCall(..., ..., ..., onSuccess(outgoingCall), ..., ...);
         * outgoingCall.getId();
         */
        this.getId = function(){
            return id;
        };

        /**
         * Force the plugin to send a IntraFrame
         *
         * @name fcs.call.OutgoingCall#sendIntraFrame
         * @function
         * @since 3.0.0
         *
         * @example
         *
         * A previously created {@link fcs.call.OutgoingCall} is required. {@see {@link fcs.call.startCall}} for more details.
         *
         * var outgoingCall = {};
         * fcs.call.startCall(..., ..., ..., onSuccess(outgoingCall), ..., ...);
         * outgoingCall.sendIntraFrame();
         */
        this.sendIntraFrame = function(){
            if (sendVideo) {
                callManager.sendIntraFrame(id);
            }
        };

        /**
         * Force the plugin to send a BlackFrame
         *
         * @name fcs.call.OutgoingCall#sendBlackFrame
         * @function
         * @since 3.0.0
         *
         * @example
         *
         * A previously created {@link fcs.call.OutgoingCall} is required. {@see {@link fcs.call.startCall}} for more details.
         *
         * var outgoingCall = {};
         * fcs.call.startCall(..., ..., ..., onSuccess(outgoingCall), ..., ...);
         * outgoingCall.sendBlackFrame();
         */
        this.sendBlackFrame = function(){
            callManager.sendBlackFrame(id);
        };

        /**
         * Force the plugin to refresh video renderer
         * with this call's remote video stream
         *
         * @name fcs.call.OutgoingCall#refreshVideoRenderer
         * @function
         * @since 3.0.0
         *
         * @example
         *
         * A previously created {@link fcs.call.OutgoingCall} is required. {@see {@link fcs.call.startCall}} for more details.
         *
         * var outgoingCall = {};
         * fcs.call.startCall(..., ..., ..., onSuccess(outgoingCall), ..., ...);
         * outgoingCall.refreshVideoRenderer();
         */
        this.refreshVideoRenderer = function(){
                callManager.refreshVideoRenderer(id);
        };

        /**
         * Puts the speaker into mute.
         *
         * @name fcs.call.OutgoingCall#mute
         * @function
         * @since 3.0.0
         *
         * @example
         *
         * A previously created {@link fcs.call.OutgoingCall} is required. {@see {@link fcs.call.startCall}} for more details.
         *
         * var outgoingCall = {};
         * fcs.call.startCall(..., ..., ..., onSuccess(outgoingCall), ..., ...);
         * outgoingCall.mute();
         */
        this.mute = function(){
            callManager.mute(id, true);
        };

        /**
         * Puts the speaker into unmute.
         *
         * @name fcs.call.OutgoingCall#unmute
         * @function
         * @since 3.0.0
         *
         * @example
         *
         * A previously created {@link fcs.call.OutgoingCall} is required. {@see {@link fcs.call.startCall}} for more details.
         *
         * var outgoingCall = {};
         * fcs.call.startCall(..., ..., ..., onSuccess(outgoingCall), ..., ...);
         * outgoingCall.unmute();
         */
        this.unmute = function(){
            callManager.mute(id, false);
        };

        /**
         * End the call
         *
         * @name fcs.call.OutgoingCall#end
         * @param {function} onSuccess The onSuccess() callback function to be called
         * @function
         * @since 3.0.0
         *
         * @example
         *
         * A previously created {@link fcs.call.OutgoingCall} is required. {@see {@link fcs.call.startCall}} for more details.
         *
         * var outgoingCall = {};
         * fcs.call.startCall(..., ..., ..., onSuccess(outgoingCall), ..., ...);
         *
         * var endCallOnSuccess = function(){
         *    //do something here
         * };
         *
         * outgoingCall.end(endCallOnSuccess);
         */
        this.end = function(onSuccess){
            callManager.end(id, onSuccess);
        };

        /**
          * Holds the call.
          * @name fcs.call.OutgoingCall#hold
          * @function
          * @since 3.0.0
          * @param {function} onSuccess The onSuccess() callback function to be called
          * @param {function} onFailure The onFailure({@link fcs.Errors}) callback function to be called
          *
          * @example
          *
          * A previously created {@link fcs.call.OutgoingCall} is required. {@see {@link fcs.call.startCall}} for more details.
          *
          * var outgoingCall = {};
          * fcs.call.startCall(..., ..., ..., onSuccess(outgoingCall), ..., ...);
          *
          * var holdCallOnSuccess = function(){
          *    //do something here
          * };
          * var holdCallOnFailure = function(err){
          *    //do something here
          * };
          *
          * outgoingCall.hold(holdCallOnSuccess, holdCallOnFailure);
          */
        this.hold = function(onSuccess, onFailure){
            callManager.hold(callid, onSuccess, onFailure);
        };

        /**
         * Resume the call.
         * @name fcs.call.OutgoingCall#unhold
         * @function
         * @since 3.0.0
         * @param {function} onSuccess The onSuccess() callback function to be called
         * @param {function} onFailure The onFailure({@link fcs.Errors}) callback function to be called
         *
         * @example
         *
         * A previously created {@link fcs.call.OutgoingCall} is required. {@see {@link fcs.call.startCall}} for more details.
         *
         * var outgoingCall = {};
         * fcs.call.startCall(..., ..., ..., onSuccess(outgoingCall), ..., ...);
         *
         * var unholdCallOnSuccess = function(){
         *    //do something here
         * };
         * var unholdCallOnFailure = function(err){
         *    //do something here
         * };
         *
         * outgoingCall.unhold(unholdCallOnSuccess, unholdCallOnFailure);
         */
        this.unhold = function(onSuccess,onFailure){
            callManager.unhold(id, onSuccess,onFailure);
        };

        this.directTransfer = function(address,onSuccess,onFailure){
            callManager.directTransfer(id, address, onSuccess,onFailure);
        };

        /**
         * Stop the video for this call after the call is established
         *
         * @name fcs.call.OutgoingCall#videoStop
         * @function
         * @since 3.0.0
         * @param {function} [onSuccess] The onSuccess() to be called when the video is stopped<br />
         * function()
         * @param {function} [onFailure] The onFailure() to be called when the video could not be stopped<br />
         * function()
         *
         * @example
         *
         * A previously created {@link fcs.call.OutgoingCall} is required. {@see {@link fcs.call.startCall}} for more details.
         *
         * var outgoingCall = {};
         * fcs.call.startCall(..., ..., ..., onSuccess(outgoingCall), ..., ...);
         *
         * var videoStopOnSuccess = function(){
         *    //do something here
         * };
         * var videoStopOnFailure = function(){
         *    //do something here
         * };
         *
         * outgoingCall.videoStop(videoStopOnSuccess, videoStopOnFailure);
         */
        this.videoStop = function(onSuccess, onFailure){
            callManager.videoStopStart(callid, onSuccess, onFailure, false);
        };

        /**
         * Start the video for this call after the call is established
         *
         * @name fcs.call.OutgoingCall#videoStart
         * @function
         * @since 3.0.0
         * @param {function} [onSuccess] The onSuccess() to be called when the video is started
         * @param {function} [onFailure] The onFailure() to be called when the video could not be started
         * @param {string} [videoQuality] Sets the quality of video, this parameter will be passed to getUserMedia()
         *                  if the video source is allowed before, this parameter will not be used
         *
         * @example
         *
         * A previously created {@link fcs.call.OutgoingCall} is required. {@see {@link fcs.call.startCall}} for more details.
         *
         * var outgoingCall = {};
         * fcs.call.startCall(..., ..., ..., onSuccess(outgoingCall), ..., ...);
         *
         * var videoStartOnSuccess = function(){
         *    //do something here
         * };
         * var videoStartOnFailure = function(){
         *    //do something here
         * };
         *
         * outgoingCall.videoStart(videoStopOnSuccess, videoStopOnFailure);
         */
        this.videoStart = function(onSuccess, onFailure, videoQuality){
            callManager.videoStopStart(callid, onSuccess, onFailure, true, videoQuality);
        };

        /**
         * Join 2 calls
         * You need two different calls to establish this functionality.
         * In order to join two calls. both calls must be put in to hold state first.
         * If not call servers will not your request.
         *
         * @name fcs.call.OutgoingCall#join
         * @function
         * @since 3.0.0
         * @param {fcs.call.Call} anotherCall Call that we want the current call to be joined to.
         * @param {function} onSuccess The onSuccess({@link fcs.call.OutgoingCall}) to be called when the call have been joined provide the joined call as parameter
         * @param {function} [onFailure] The onFailure() to be called when media could not be join
         *
         * @example
         *
         * A previously created {@link fcs.call.OutgoingCall} is required. {@see {@link fcs.call.startCall}} for more details.
         *
         * var outgoingCall = {};
         * fcs.call.startCall(..., ..., ..., onSuccess(outgoingCall), ..., ...);
         *
         * And another {@link fcs.call.OutgoingCall} or {@link fcs.call.IncomingCall} is requeired which is going to be joined.
         * var anotherCall; // assume this is previosuly created.
         *
         * var joinOnSuccess = function(joinedCall){
         *    joinedCall // newly created.
         *    //do something here
         * };
         * var joinOnFailure = function(){
         *    //do something here
         * };
         *
         * outgoingCall.join(anotherCall, joinOnSuccess, joinOnFailure);
         *
         * When join() is successfuly compeled, joinOnSuccess({@link fcs.call.OutgoingCall}) will be invoked.
         */
        this.join = function(anotherCall, onSuccess, onFailure){
            callManager.join(id, anotherCall.getId(), onSuccess, onFailure);
        };

        /**
         * Send Dual-tone multi-frequency signaling.
         *
         * @name fcs.call.OutgoingCall#sendDTMF
         * @function
         * @since 3.0.0
         * @param {String} tone Tone to be send as dtmf.
         *
         * @example
         *
         * A previously created {@link fcs.call.OutgoingCall} is required. {@see {@link fcs.call.startCall}} for more details.
         *
         * var outgoingCall = {};
         * fcs.call.startCall(..., ..., ..., onSuccess(outgoingCall), ..., ...);
         *
         * var videoStartOnSuccess = function(){
         *    //do something here
         * };
         * var videoStartOnFailure = function(){
         *    //do something here
         * };
         *
         * outgoingCall.sendDTMF("0");
         */
        this.sendDTMF = function(tone){
            callManager.sendDTMF(id, tone);
        };

        /**
         * Returns the call is a join call or not
         * Do not use this function if you really dont need it.
         * This will be handled by the framework
         *
         * @name fcs.call.OutgoingCall#getJoin
         * @function
         * @since 3.0.0
         * @returns {Boolean} isJoin
         *
         * @example
         *
         * A previously created {@link fcs.call.OutgoingCall} is required. {@see {@link fcs.call.startCall}} for more details.
         *
         * var outgoingCall = {};
         * fcs.call.startCall(..., ..., ..., onSuccess(outgoingCall), ..., ...);
         *
         * var videoStartOnSuccess = function(){
         *    //do something here
         * };
         * var videoStartOnFailure = function(){
         *    //do something here
         * };
         *
         * outgoingCall.getJoin();
         *
         * This method will return true if the outgoingCall is a previously joined call {@see {@link fcs.call.outgoingCall#join}}.
         */
        this.getJoin = function() {
            return isJoin;
        };

        /**
         * Marks the call as a join call or not
         * Do not use this function if you really dont need it.
         * This will be handled by the framework
         *
         * @name fcs.call.OutgoingCall#setJoin
         * @function
         * @since 3.0.0
         * @param {String} join
         *
         * @example
         *
         * When an outgoing call is received, {@link fcs.call.event:onReceived} handler will be invoked.
         *
         * var outgoingCall = {};
         * fcs.call.onReceived = function(call) {
         *    outgoingCall = call;
         * };
         *
         * outgoingCall.setJoin(true);
         */
        this.setJoin = function (join) {
            isJoin = join;
        };

        /**
         * Returns the button is a disabled or not
         * You may want to disable your buttons while waiting for a response.
         * Ex: this will prevent clicking multiple times for hold button until first hold response is not recieved
         *
         * @name fcs.call.OutgoingCall#getButtonDisabler
         * @function
         * @since 3.0.0
         * @returns {Boolean} buttonDisabler
         *
         * @example
         *
         * When an outgoing call is received, {@link fcs.call.event:onReceived} handler will be invoked.
         *
         * var outgoingCall = {};
         * fcs.call.onReceived = function(call) {
         *    outgoingCall = call;
         * };
         *
         * outgoingCall.getButtonDisabler();
         */
        this.getButtonDisabler = function() {
            return buttonDisabler;
        };

        /**
         * Clears the timer set with fcs.call.IncomingCall#setButtonDisabler.
         * You may want to disable your buttons while waiting for a response.
         * Ex: this will prevent clicking multiple times for hold button until first hold response is not recieved
         *
         * @name fcs.call.OutgoingCall#clearBtnTimeout
         * @function
         * @since 3.0.0
         *
         * @example
         *
         * When an outgoing call is received, {@link fcs.call.event:onReceived} handler will be invoked.
         *
         * var outgoingCall = {};
         * fcs.call.onReceived = function(call) {
         *    outgoingCall = call;
         * };
         *
         * outgoingCall.clearBtnTimeout();
         */
        this.setButtonDisabler = function(disable) {
            buttonDisabler = disable;
            if(buttonDisabler) {
                btnTimeout = setTimeout( function() {
                    buttonDisabler = false;
                },
                4000 );
            }
        };

        /**
         * Clears the timer set with fcs.call.IncomingCall#setButtonDisabler.
         * You may want to disable your buttons while waiting for a response.
         * Ex: this will prevent clicking multiple times for hold button until first hold response is not recieved
         *
         * @name fcs.call.OutgoingCall#clearBtnTimeout
         * @function
         * @since 3.0.0
         *
         * @example
         *
         * When an outgoing call is received, {@link fcs.call.event:onReceived} handler will be invoked.
         *
         * var outgoingCall = {};
         * fcs.call.onReceived = function(call) {
         *    outgoingCall = call;
         * };
         *
         * outgoingcall.clearBtnTimeout();
         */
        this.clearBtnTimeout = function() {
            clearTimeout(btnTimeout);
        };

        /**
        * Long call audit
        * Creates a timer after call is established.
        * This timer sends a "PUT" request to server.
        * This will continue until one request fails.
        * Handled by framework. You dont need to call this function
        *
        * @name fcs.call.OutgoingCall#setAuditTimer
        * @function
        * @since 3.0.0
        *
        * @example
        *
        * When an incoming call is received, {@link fcs.call.event:onReceived} handler will be invoked.
        * incomingCall.setAuditTimer(audit);
        */
        this.setAuditTimer = function (audit) {
            auditTimer = setInterval(function() {
                audit();
            },
            fcsConfig.callAuditTimer ? fcsConfig.callAuditTimer:30000);
        };


        /**
        * Clears the long call audit prior to clearing all call resources.
        * Handled by framework. you dont need to call this function
        *
        * @name fcs.call.OutgoingCall#clearAuditTimer
        * @function
        * @since 3.0.0
        *
        * @example
        *
        * When an outgoing call is received, {@link fcs.call.event:onReceived} handler will be invoked.
        */
        this.clearAuditTimer = function() {
            clearInterval(auditTimer);
        };

        this.isCallMuted = function(id) {
            return callManager.isCallMuted(id);
        };

        /**
         * Returns video negotation availability
         * @name fcs.call.OutgoingCall#isVideoNegotationAvailable
         * @function
         * @since 3.0.1
         * @example
         * A previously created {@link fcs.call.OutgoingCall} is required. {@see {@link fcs.call.startCall}} for more details.
         *
         * var outgoingCall = {};
         * fcs.call.startCall(..., ..., ..., onSuccess(outgoingCall), ..., ...);
         * outgoingCall.isVideoNegotationAvailable(id);
         */
        this.isVideoNegotationAvailable = function(id) {
            return callManager.isVideoNegotationAvailable(id);
        };

        /**
         * Returns the state of the remote video.
         * @name fcs.call.IncomingCall#getRemoteVideoState
         * @function
         * @since 3.0.6
         */
        this.getRemoteVideoState = function() {
            return callManager.getRemoteVideoState(this.getId());
        };
    };

    this.OutgoingCall.prototype = new this.Call();
    if (__testonly__) { this.setNotificationState = function(_notificationState){ this.notificationState=_notificationState;}; }

};

CallTrigger.prototype = new Call();
fcs.call = new CallTrigger();
if (__testonly__) { __testonly__.Call = Call; }
if (__testonly__) { __testonly__.OutgoingCall = fcs.call.OutgoingCall;}

/**
* Handles receiving of custom messages (Custom).
*
* @name custom
* @namespace
* @memberOf fcs
*
* @version 3.0.4
* @since 3.0.0
*/
var Custom = function() {

   /**
    * Called on receipt of an instant message
    *
    * @name fcs.custom.onReceived
    * @event
    * @param {fcs.custom.Message} custom Message received
    * @since 3.0.0
    * @example
    * var messageReceived = function(msg){
    *    // do something here
    * };
    *
    * fcs.custom.onReceived = messageReceived;
    */

};

var CustomImpl = function() {
    this.onReceived = null;
};

CustomImpl.prototype = new Custom();
fcs.custom = new CustomImpl();

NotificationCallBacks.custom = function(data) {
    utils.callFunctionIfExist(fcs.custom.onReceived, data);
};
var NotificationImpl = function() {

    var SUBSCRIPTION_URL = "/subscription",
        CONNECTION_URL = "/rest/version/latest/isAlive",
    SUBSCRITION_KEYS_FOR_ASSIGNED_SERVICES = {
        "CallControl": "call",
        "call" : "call",
        "IM": "IM",
        "Presence": "Presence",
        "custom": "custom",
        "callMe": "callMe",
        "Conversation": "conversation",
        "conversation": "conversation"
    },
    DEFAULT_SERVICES = [SUBSCRITION_KEYS_FOR_ASSIGNED_SERVICES.IM,
                        SUBSCRITION_KEYS_FOR_ASSIGNED_SERVICES.Presence,
                        SUBSCRITION_KEYS_FOR_ASSIGNED_SERVICES.CallControl],
    DEFAULT_ANONYMOUS_SERVICES = [SUBSCRITION_KEYS_FOR_ASSIGNED_SERVICES.callMe],
    DEFAULT_SUBSCRIPTION_EXPIRY_VALUE = 3600;

    function getNotificationType() {
        // if SNMP is set return specific data to be sent to the server
        if(fcsConfig.notificationType === fcs.notification.NotificationTypes.WEBSOCKET && window.WebSocket){
            return {
                notificationType: "WebSocket",
                clientIp: fcsConfig.clientIp
            };
        }
        else {
            fcsConfig.notificationType = "longpolling";
            return {
                notificationType: "LongPolling",
                pollingTimer: fcsConfig.polling
            };
        }
    }

    function composeServicesToSubscribeFromAssignedServices(assignedServices) {
        var i, services = [];
        for (i in SUBSCRITION_KEYS_FOR_ASSIGNED_SERVICES) {
            if (SUBSCRITION_KEYS_FOR_ASSIGNED_SERVICES.hasOwnProperty(i)) {
                if (assignedServices.indexOf(i) !== -1) {
                    services.push(SUBSCRITION_KEYS_FOR_ASSIGNED_SERVICES[i]);
                }
            }
        }

        return services;
    }

    function composeSubscribeRequestData(forceLogout, isSubscribe) {
        var notificationTypeData = getNotificationType(),
        i,
        subscribeRequest;

        if (fcs.notification.isAnonymous()) {
            if (!fcsConfig.anonymousServices) {
                fcsConfig.anonymousServices = DEFAULT_ANONYMOUS_SERVICES;
            }
        }
        else {
            if (!fcsConfig.services) {
                fcsConfig.services = DEFAULT_SERVICES;
            }
        }

        subscribeRequest = {
                "expires": Math.floor(fcsConfig.expires),
                "service": fcs.notification.isAnonymous() ? composeServicesToSubscribeFromAssignedServices(fcsConfig.anonymousServices) : composeServicesToSubscribeFromAssignedServices(fcsConfig.services),
                "localization": "English_US"
        };

        if (isSubscribe && fcsConfig.serverProvidedTurnCredentials) {
            subscribeRequest.useTurn = (fcsConfig.serverProvidedTurnCredentials === true ? true : false);
        }

        if (forceLogout === true) {
            subscribeRequest.forceLogOut = "true";
        }

        for (i in notificationTypeData) {
            if(notificationTypeData.hasOwnProperty(i)) {
                subscribeRequest[i] = notificationTypeData[i];
            }
        }

        return subscribeRequest;
    }

    this.extendSubscription = function(subscriptionURL, onSuccess, onFailure) {
        if (fcsConfig.expires === 0) {
            fcsConfig.expires = DEFAULT_SUBSCRIPTION_EXPIRY_VALUE;
        }

        server.sendPutRequest(
            {
                url: getUrl() + subscriptionURL,
                data: {"subscribeRequest": composeSubscribeRequestData()}
            },
            function(data) {
                var response = data.subscribeResponse, params = response.subscriptionParams;
                onSuccess(params.notificationChannel, params.assignedService, params.service);
            },
            onFailure
            );
    };

    this.retrieveNotification = function(notificationChannelURL, onSuccess, onFailure) {
        return server.sendGetRequest(
            {
                url: getUrl() + notificationChannelURL
            },
            function(data){
                var type = null, notificationMessage;
                if(data !== null){
                    notificationMessage = data.notificationMessage;
                    if(notificationMessage){
                        type = notificationMessage.eventType;
                    }
                }
                onSuccess(type, notificationMessage);
            }
            ,
            onFailure
            );
    };

    this.subscribe = function(onSuccess, onFailure ,forceLogout, token) {
        var dummy, realm = getRealm();
        fcsConfig.expires = DEFAULT_SUBSCRIPTION_EXPIRY_VALUE;
        server.sendPostRequest(
        {
            url: getWAMUrl(1, SUBSCRIPTION_URL + (realm?("?tokenrealm=" + realm):"")),
            data: {"subscribeRequest": composeSubscribeRequestData(forceLogout, true)}
        },
        function(data) {
            var response = data.subscribeResponse, params = response.subscriptionParams, turnParams;
            if (params.turnActive === true) {
                if (params.turnCredentials && params.turnCredentials.username && params.turnCredentials.password) {
                    turnParams = {username : params.turnCredentials.username, credential : params.turnCredentials.password};
                    globalBroadcaster.publish(CONSTANTS.EVENT.TURN_CREDENTIALS_ESTABLISHED, turnParams);
                }
            }
            onSuccess(response.subscription,
                params.notificationChannel,
                params.expires,
                params.pollingTimer,
                params.assignedService,
                params.service,
                params.sessionId);
        },
        onFailure, dummy, dummy, dummy, dummy, token
        );
    };

    this.deleteSubscription = function(subscriptionURL, onSuccess, onFailure, synchronous) {
        server.sendDeleteRequest({
            url: getUrl() + subscriptionURL
        },
        onSuccess,
        onFailure
        );
    };

    if (__testonly__) { this.composeSubscribeRequestData = composeSubscribeRequestData;}
};

NotificationImpl.prototype = new Notification();

NotificationCallBacks.gone = function(data) {
    notificationManager.onGoneNotificationReceived(data);
};

var NotificationManager = function() {
    var logger = logManager.getLogger("notificationManager"),
            SUBSCRIBEURL = 'SubscriptionUrl',
            NOTIFYURL = 'NotificationUrl',
            NOTIFYID = 'NotificationId',
            SUBSCRIBEEXPIRY = 'SubscriptionExpiry',
            SUBSCRIBEEXTENDINTERVAL = 'SubscriptionExtendInterval',
            USERNAME = 'USERNAME',
            SESSION = 'SESSION',
            NOTIFICATION_EVENTS_QUEUE_MAX_LENGTH = 50,
            NOTIFICATION_EVENTS_QUEUE_CLEARING_AUDIT_INTERVAL = 600,
            CHECK_CONNECTIVITY_INTERVAL = 10000,
            RESTART_SUBSCRIPTION_TIMEOUT = CHECK_CONNECTIVITY_INTERVAL + 1000,
            notificationRetry = 4000,
            WEBSOCKET_CONSTANTS = CONSTANTS.WEBSOCKET,
            notifier = null,
            webSocket = null,
            self = this,
            isAnonymous = false,
            service = new NotificationImpl(),
            // function to be invoked on failure (must be set by the user)
            onNotificationFailure = null,
            onNotificationSuccess = null,
            isNotificationFailureDetected = false,
            extendNotificationSubscription, notificationSuccess, notificationFailure,
            extendNotificationSubscriptionTimer = null,
            webSocketConnect,
            onConnectionLost,
            onConnectionEstablished,
            triggeredFetch = false,
            onSubscriptionSuccess = null,
            onSubscriptionFailure = null,
            notificationEventsQueue = [],
            notificationEventsQueueClearingAuditTimer,
            notificationCachePrefix = "",
            startNotificationTimerAfterConnectionReEstablished,
            restartSubscriptionTimer,
            notificationFailureRestartSubscriptionTimeout,
            lastLongpollingRequest = null,
            originalNotificationType = null,
            token = null,
            session = null;

    function onTokenAuth(data){
        token = data.token;
    }

    function cancelLastLongpollingRequest() {
        if (lastLongpollingRequest) {
            logger.trace("aborting last long polling request.");
            lastLongpollingRequest.abort();
            lastLongpollingRequest = null;
        }
    }

    function onTokenOrSessionError(){
        notifier = null;
        triggeredFetch = false;

        cache.removeItem(notificationCachePrefix + NOTIFYURL);
        cache.removeItem(notificationCachePrefix + NOTIFYID);
        cache.removeItem(notificationCachePrefix + SUBSCRIBEURL);
        cache.removeItem(notificationCachePrefix + SUBSCRIBEEXPIRY);
        cache.removeItem(notificationCachePrefix + SUBSCRIBEEXTENDINTERVAL);
        cache.removeItem(notificationCachePrefix + SESSION);
        this.onGoneNotificationReceived();
        cancelLastLongpollingRequest();
    }

    function publishDeviceSubscriptionStartedMessage(message) {
        globalBroadcaster.publish(CONSTANTS.EVENT.DEVICE_SUBSCRIPTION_STARTED, message);
    }

    function publishDeviceSubscriptionEndedMessage() {
        globalBroadcaster.publish(CONSTANTS.EVENT.DEVICE_SUBSCRIPTION_ENDED);
    }

    function notificationEventsQueueClearingAudit() {
        if (notificationEventsQueue.length > 0) {
            var eventIdtoRemove = notificationEventsQueue.shift();
            logger.info("notification events queue clearing audit timer has expired, removing first eventId: " + eventIdtoRemove);
        }
    }

    notificationEventsQueueClearingAuditTimer = setInterval(notificationEventsQueueClearingAudit, NOTIFICATION_EVENTS_QUEUE_CLEARING_AUDIT_INTERVAL * 1000);

    this.NotificationTypes = {
        LONGPOLLING: "longpolling",
        SNMP: "snmp",
        WEBSOCKET: "websocket"
    };

    this.isAnonymous = function() {
        return isAnonymous;
    };

    function getNotificationType() {

        var type;
        for (type in self.NotificationTypes) {
            if (self.NotificationTypes.hasOwnProperty(type)) {
                if (fcsConfig.notificationType === self.NotificationTypes[type]) {
                    return fcsConfig.notificationType;
                }
            }
        }

        return self.NotificationTypes.WEBSOCKET;
    }

    function isNotificationTypeLongPolling() {
        // If user set long polling return true
        return (getNotificationType() === self.NotificationTypes.LONGPOLLING);
    }

    function isNotificationTypeWebSocket() {
        // If user set websocket return true
        return window.WebSocket && (getNotificationType() === self.NotificationTypes.WEBSOCKET);
    }

    function stopRestartSubscriptionTimer() {
        clearTimeout(restartSubscriptionTimer);
        restartSubscriptionTimer = null;
    }

    function restartSubscription(toLP) {
        stopRestartSubscriptionTimer();
        restartSubscriptionTimer = setTimeout(function() {
            if (!fcs.isConnected()) {
                logger.debug("Connection is lost, no need to restart subscription...");
                return;
            }

            logger.debug("Restarting subscription...");
            if (toLP) {
                logger.debug("Switching to Long Polling notification...");
                fcsConfig.notificationType = self.NotificationTypes.LONGPOLLING;
            }

            self.start(onSubscriptionSuccess, onSubscriptionFailure, isAnonymous, undefined, undefined, true);

        }, RESTART_SUBSCRIPTION_TIMEOUT);
    }

    function isWebsocketOpened() {
        if (webSocket && webSocket.readyState === webSocket.OPEN) {
            return true;
        }
        return false;
    }

    function validateWebsocketUrl() {
        if (!isWebsocketOpened()) {
            return false;
        }

        if (!notifier) {
            return false;
        }

        if (!notifier.notificationUrl) {
            return false;
        }

        if (webSocket.url.indexOf(notifier.notificationUrl) === -1) {
            return false;
        }

        return true;
    }

    function websocketConnectionCheck() {
        if (isWebsocketOpened()) {
            webSocket.send("test");
        }
    }

    function fetchNotification() {
        if (notifier) {
            if (lastLongpollingRequest) {
                logger.info("longpolling request exists, no need to trigger new one.");
                return;
            }
            //Fetching Notification
            lastLongpollingRequest = service.retrieveNotification(notifier.notificationUrl, notificationSuccess, notificationFailure);
        }
        else {
            logger.error("notifier is undefined, cannot fetch notification");
        }
    }

    // Handles successfully fetched notification
    notificationSuccess = function(type, data) {
        var eventIdtoRemove;
        if (data && type) {
            logger.info("received notification event:" + type, data);
            if (notificationEventsQueue.indexOf(data.eventId) !== -1) {
                logger.info("previously received notification eventId: " + data.eventId + ", do not execute notification callback function.");
            }
            else {
                logger.info("newly received notification eventId: " + data.eventId);
                notificationEventsQueue.push(data.eventId);
                if (notificationEventsQueue.length === NOTIFICATION_EVENTS_QUEUE_MAX_LENGTH) {
                    eventIdtoRemove = notificationEventsQueue.shift();
                    logger.info("notification events queue is full, remove first eventId: " + eventIdtoRemove);
                }
                utils.callFunctionIfExist(NotificationCallBacks[type], data);
            }
        }

        // if 'Long polling' is used, fetch the notification
        if (isNotificationTypeLongPolling()) {
            lastLongpollingRequest = null;
            fetchNotification();
        }

        if (isNotificationFailureDetected) {
            isNotificationFailureDetected = false;
            utils.callFunctionIfExist(onNotificationSuccess);
        }

    };

    function stopNotificationFailureRestartSubscriptionTimeoutTimer() {
        clearTimeout(notificationFailureRestartSubscriptionTimeout);
        notificationFailureRestartSubscriptionTimeout = null;
    }

    // Handles fail fetched notification
    notificationFailure = function(error) {
        logger.error("received notification error:" + error);
        globalBroadcaster.publish(CONSTANTS.EVENT.NOTIFICATION_CHANNEL_LOST);
        if (!fcs.isConnected()) {
            logger.debug("Connection is lost, no need to handle notification failure...");
            return;
        }

        isNotificationFailureDetected = true;

        // if 'Long polling' is used, fetch the notification
        if (isNotificationTypeLongPolling()) {
            stopNotificationFailureRestartSubscriptionTimeoutTimer();
            notificationFailureRestartSubscriptionTimeout = setTimeout(function() {
                restartSubscription();
            }, notificationRetry);
        }

        utils.callFunctionIfExist(onNotificationFailure, error);
    };

    function websocketDisconnect() {
        if (webSocket) {
            webSocket.onmessage = null;
            webSocket.onopen = null;
            webSocket.onclose = null;
            webSocket.onerror = null;
            if (webSocket.close) {
                webSocket.close();
            }
            webSocket = null;
        }
    }

    webSocketConnect = function(onSuccess, onFailure) {
        var protocolValue = WEBSOCKET_CONSTANTS.PROTOCOL.NONSECURE;

        function callOnSuccess(status) {
            logger.trace("websocket connection created successfully: " + status);
            if (typeof onSuccess === 'function') {
                onSuccess(status);
            }
        }

        function callOnFailure(status) {
            logger.trace("websocket connection failed: " + status);
            // this is just for clearing local web socket variable.
            websocketDisconnect();
            if (typeof onFailure === 'function') {
                onFailure(status);
            }
        }

        if (isWebsocketOpened()) {
            if (validateWebsocketUrl()) {
                logger.info("WebSocket is already opened, no need to open new one.");
                callOnSuccess(WEBSOCKET_CONSTANTS.STATUS.ALREADY_OPENED);
                return;
            }

            logger.error("websocket connection with invalid url is found!");
            websocketDisconnect();
        }
        else {
            // this is just for clearing local web socket variable.
            websocketDisconnect();
        }

        try {
            if (fcsConfig.websocketProtocol) {
                if (fcsConfig.websocketProtocol === WEBSOCKET_CONSTANTS.PROTOCOL.SECURE) {
                    protocolValue = WEBSOCKET_CONSTANTS.PROTOCOL.SECURE;
                }
            }
            webSocket = new window.WebSocket(protocolValue + "://" + (fcsConfig.websocketIP ? fcsConfig.websocketIP : window.location.hostname) + ":" + (fcsConfig.websocketPort ? fcsConfig.websocketPort : WEBSOCKET_CONSTANTS.DEFAULT_PORT) + notifier.notificationUrl);
        }
        catch (exception) {
            logger.error("WebSocket create error: ", exception);
            callOnFailure(WEBSOCKET_CONSTANTS.STATUS.CREATE_ERROR);
            return;
        }

        if (webSocket !== null) {
            webSocket.onmessage = function(event) {
                var data = JSON.parse(event.data), notificationMessage, type;
                if (data) {
                    //logger.info("WebSocket notification event data:" + data);
                    notificationMessage = data.notificationMessage;
                    //logger.info("WebSocket notification event notificationMessage:" + notificationMessage);
                    if (notificationMessage) {
                        type = notificationMessage.eventType;
                        notificationSuccess(type, notificationMessage);
                    }
                }
            };
            webSocket.onopen = function(event) {
                logger.info("WebSocket opened");
                callOnSuccess(WEBSOCKET_CONSTANTS.STATUS.OPENED);
            };
            webSocket.onclose = function(event) {
                logger.info("WebSocket closed");
                notificationFailure(WEBSOCKET_CONSTANTS.STATUS.CONNECTION_CLOSED);
                callOnFailure(WEBSOCKET_CONSTANTS.STATUS.CONNECTION_CLOSED);
            };
            webSocket.onerror = function(event) {
                logger.error("Error on Web Socket connection.");
                notificationFailure(WEBSOCKET_CONSTANTS.STATUS.CONNECTION_ERROR);
                callOnFailure(WEBSOCKET_CONSTANTS.STATUS.CONNECTION_ERROR);
            };
        }
        else {
            callOnFailure(WEBSOCKET_CONSTANTS.STATUS.NOT_FOUND);
        }
    };

     function onNotificationSubscriptionSuccess() {
        publishDeviceSubscriptionStartedMessage({"connectivity": {
                "handler": websocketConnectionCheck,
                "interval": CHECK_CONNECTIVITY_INTERVAL
            },
            "session": session,
            "notificationId": notifier ? notifier.notificationId : ""
         });
        if (onSubscriptionSuccess) {
            utils.callFunctionIfExist(onSubscriptionSuccess);
            onSubscriptionSuccess = null;
        }
    }

    function onDeviceSubscriptionFailure(err) {
        if (fcs.isConnected()) {
            utils.callFunctionIfExist(onSubscriptionFailure, err);
        }
    }

    function stopExtendNotificationSubscriptionTimer() {
        logger.info("extend notification subscription timer is stopped.");
        clearInterval(extendNotificationSubscriptionTimer);
        extendNotificationSubscriptionTimer = null;
    }

    // Subscribe for getting notifications
    function deviceSubscribe(forceLogout) {
        if (!fcs.isConnected()) {
            logger.debug("Connection is lost, no need to subscribe...");
            return;
        }

        logger.debug("Subscribing...");
        service.subscribe(function(subscribeUrl, notificationUrl, exp, poll, assignedService, servicesReceivingNotification, sessionId) {
            token = null;
            fcs.setServices(assignedService);
            fcsConfig.services = assignedService;
            fcsConfig.servicesReceivingNotification = servicesReceivingNotification;

            fcsConfig.polling = poll;
            fcsConfig.expires = exp;
            fcsConfig.extendInterval = exp / 2;
            notifier = {};
            notifier.subscribeUrl = subscribeUrl;
            notifier.notificationUrl = notificationUrl;
            notifier.notificationId = notificationUrl.substr(notificationUrl.lastIndexOf("/") + 1);
            stopExtendNotificationSubscriptionTimer();
            extendNotificationSubscriptionTimer = setInterval(extendNotificationSubscription, fcsConfig.extendInterval * 1000);
            cache.setItem(notificationCachePrefix + NOTIFYURL, notificationUrl);
            cache.setItem(notificationCachePrefix + NOTIFYID, notifier.notificationId);
            cache.setItem(notificationCachePrefix + SUBSCRIBEURL, subscribeUrl);
            cache.setItem(notificationCachePrefix + SUBSCRIBEEXPIRY, fcsConfig.expires);
            cache.setItem(notificationCachePrefix + SUBSCRIBEEXTENDINTERVAL, fcsConfig.extendInterval);
            cache.setItem(notificationCachePrefix + USERNAME, fcs.getUser());
            if (sessionId) {
                session = sessionId;
                cache.setItem(notificationCachePrefix + SESSION, session);
            }

            logger.debug("Subscription successfull - notifier: ", notifier);

            // if 'WebSocket' initialize else 'LongPolling' is used, fetch the notification
            if (isNotificationTypeWebSocket()) {
                webSocketConnect(function () {
                    originalNotificationType = self.NotificationTypes.WEBSOCKET;
                    cancelLastLongpollingRequest();
                    onNotificationSubscriptionSuccess();
                }, function() {
                    restartSubscription(true);
                });
            }
            else {
                originalNotificationType = self.NotificationTypes.LONGPOLLING;
                cancelLastLongpollingRequest();
                onNotificationSubscriptionSuccess();
                fetchNotification();
            }
        }, function(err) {
            logger.error("Subscription is failed - error: " + err);

            onDeviceSubscriptionFailure(err);
        },forceLogout, token);
    }

    function sendExtendSubscriptionRequest() {
        if (!fcs.isConnected()) {
            logger.debug("Connection is lost, no need to extend subscribe...");
            return;
        }

        logger.debug("Extending subscription... - notifier: ", notifier);
        service.extendSubscription(notifier.subscribeUrl, function(notificationChannel, assignedService, servicesReceivingNotification) {
            fcs.setServices(assignedService);
            fcsConfig.services = assignedService;
            fcsConfig.servicesReceivingNotification = servicesReceivingNotification;

            notifier.notificationUrl = notificationChannel;
            cache.setItem(notificationCachePrefix + NOTIFYURL, notificationChannel);

            //we tried to use precached subscription and it succeed start fetching notifications
            stopExtendNotificationSubscriptionTimer();
            extendNotificationSubscriptionTimer = setInterval(extendNotificationSubscription, fcsConfig.extendInterval * 1000);

            logger.debug("Extending subscription successful - notifier: ", notifier);

            // if 'WebSocket' initialize else 'LongPolling' is used, fetch the notification
            if (isNotificationTypeWebSocket()) {
                webSocketConnect(function() {
                    cancelLastLongpollingRequest();
                    onNotificationSubscriptionSuccess();
                }, function() {
                    restartSubscription(true);
                });
            }
            else {
                cancelLastLongpollingRequest();
                fetchNotification();
                onNotificationSubscriptionSuccess();
            }
        }, function(err) {
            logger.error("Extending subscription is failed - error: " + err);
            logger.error("Fail reusing existing subscription, re-subscribing.");
            cancelLastLongpollingRequest();
            deviceSubscribe();
        });
    }

    extendNotificationSubscription = function(onSuccess, onFailure, restarting) {
        if (!fcs.isConnected()) {
            logger.debug("Connection is lost, no need to extend subscribe...");
            return;
        }

        if (onSuccess) {
            onSubscriptionSuccess = onSuccess;
            onSubscriptionFailure = onFailure;
        }

         if (notifier) {
            if (!restarting) {
                if (originalNotificationType === self.NotificationTypes.WEBSOCKET
                        && isNotificationTypeLongPolling()) {
                    logger.trace("original notification type is websocket, try websocket connection again.");
                    notifier.notificationUrl.replace("/notification/", "/websocket/");
                    webSocketConnect(function() {
                        logger.trace("websocket connection created successfully, use websocket from now on.");
                        cache.setItem(notificationCachePrefix + NOTIFYURL, notifier.notificationUrl);
                        fcsConfig.notificationType = self.NotificationTypes.WEBSOCKET;
                        sendExtendSubscriptionRequest();
                    }, function() {
                        logger.trace("websocket connection failed, keep using long polling.");
                        notifier.notificationUrl.replace("/websocket/", "/notification/");
                        sendExtendSubscriptionRequest();
                    });
                }
                else {
                    sendExtendSubscriptionRequest();
                }
            }
            else {
                logger.trace("subscription restart is triggered...");
                sendExtendSubscriptionRequest();
            }

        }
        else {
            logger.debug("Cannot reuse existing subscription, re-subscribing.");
            deviceSubscribe();
        }
    };

    this.stop = function(onStopSuccess, onStopFailure, synchronous) {
        if (!fcs.isConnected()) {
            logger.debug("Connection is lost, no need to unsubscribe...");
            return;
        }

        logger.debug("Unsubscribing... - notifier: ", notifier);
        if (notifier) {
            service.deleteSubscription(notifier.subscribeUrl, function() {
                logger.debug("Unsubscription successfull");

                stopExtendNotificationSubscriptionTimer();
                publishDeviceSubscriptionEndedMessage();
                cancelLastLongpollingRequest();
                notifier = null;
                triggeredFetch = false;

                cache.removeItem(notificationCachePrefix + NOTIFYURL);
                cache.removeItem(notificationCachePrefix + NOTIFYID);
                cache.removeItem(notificationCachePrefix + SUBSCRIBEURL);
                cache.removeItem(notificationCachePrefix + SUBSCRIBEEXPIRY);
                cache.removeItem(notificationCachePrefix + SUBSCRIBEEXTENDINTERVAL);
                cache.removeItem(notificationCachePrefix + SESSION);
                if (typeof onStopSuccess === 'function') {
                    onStopSuccess();
                }
            }, function(err) {
                logger.error("Unsubscribe if failed - error:" + err);
                triggeredFetch = false;
                if (typeof onStopFailure === 'function') {
                    onStopFailure();
                }
            }, synchronous);
        }
        else {
            logger.error("notifier is unknown, cannot send unsubscribe request.");
            triggeredFetch = false;
            if (typeof onStopFailure === 'function') {
                onStopFailure();
            }
        }
    };

    function startNotification(onSuccess, onFailure, anonymous, cachePrefix ,forceLogout, restarting) {
        onSubscriptionSuccess = onSuccess;
        onSubscriptionFailure = onFailure;
        isAnonymous = anonymous;

        if (cachePrefix) {
            notificationCachePrefix = cachePrefix;
        }

        if (!fcs.isConnected()) {
            logger.debug("Connection is lost, no need to subscribe...");
            return;
        }


        logger.debug("start - notification subscription...");

        var nurl = cache.getItem(notificationCachePrefix + NOTIFYURL),
                nid = cache.getItem(notificationCachePrefix + NOTIFYID),
                surl = cache.getItem(notificationCachePrefix + SUBSCRIBEURL),
                exp = cache.getItem(notificationCachePrefix + SUBSCRIBEEXPIRY),
                extendInterval = cache.getItem(notificationCachePrefix + SUBSCRIBEEXTENDINTERVAL),
                user = cache.getItem(notificationCachePrefix + USERNAME);

        logger.debug("start - cached data - nurl: " + nurl +
                " nid: " + nid + " surl: " + surl +
                " exp: " + exp + " extendInterval: " + extendInterval +" user: " + user);

        if (nurl && nid && surl && exp && extendInterval && (fcs.getUser() === user)) {
            notifier = {};
            notifier.subscribeUrl = surl;
            notifier.notificationUrl = nurl;
            notifier.notificationId = nid;
            fcsConfig.expires = exp;
            fcsConfig.extendInterval = extendInterval;
            extendNotificationSubscription(undefined, undefined, restarting);
        }
        else {
            deviceSubscribe(forceLogout);
        }
    }

    this.start = startNotification;

    /**
     * Extending subscription and fetch the notifications
     *
     * @name fcs.notification.extend
     * @function
     */
    this.extend = startNotification;

    function stopStartNotificationTimerAfterConnectionReEstablishedTimer() {
        clearTimeout(startNotificationTimerAfterConnectionReEstablished);
        startNotificationTimerAfterConnectionReEstablished = null;
    }

    function handleConnectionEstablished() {
        var startNotificationTimeout;
        startNotificationTimeout = Math.random() * RESTART_SUBSCRIPTION_TIMEOUT;
        logger.info("starting notification after timeout: " + startNotificationTimeout);
        stopStartNotificationTimerAfterConnectionReEstablishedTimer();
        startNotificationTimerAfterConnectionReEstablished = setTimeout(function() {
            startNotification(onSubscriptionSuccess,
                    onSubscriptionFailure);
            if (fcs.isConnected()) {
                utils.callFunctionIfExist(onConnectionEstablished);
            }
        }, startNotificationTimeout);
    }

    function handleConnectionLost(err) {
        stopExtendNotificationSubscriptionTimer();
        stopStartNotificationTimerAfterConnectionReEstablishedTimer();
        if (isNotificationTypeLongPolling()) {
            cancelLastLongpollingRequest();
        }

        utils.callFunctionIfExist(onConnectionLost);
    }

    this.setOnError = function(callback) {
        onNotificationFailure = callback;
    };

    this.setOnSuccess = function(callback) {
        onNotificationSuccess = callback;
    };

    this.setOnConnectionLost = function(callback) {
        onConnectionLost = callback;
    };

    this.setOnConnectionEstablished = function(callback) {
        onConnectionEstablished = callback;
    };

    this.trigger = function() {
        if (!triggeredFetch) {
            try {
                fetchNotification();
                triggeredFetch = true;
            }
            catch (err) {
                throw err;
            }
        }
    };

    this.onGoneNotificationReceived = function(data) {
        cache.removeItem("USERNAME");
        cache.removeItem("PASSWORD");
        cache.removeItem(notificationCachePrefix + SESSION);
        stopExtendNotificationSubscriptionTimer();
        publishDeviceSubscriptionEndedMessage();
        utils.callFunctionIfExist(fcs.notification.onGoneReceived, data);
    };

    this.getNotificationId = function() {
        if (notifier) {
            return notifier.notificationId;
        }
    };

    globalBroadcaster.subscribe(CONSTANTS.EVENT.CONNECTION_REESTABLISHED, handleConnectionEstablished);
    globalBroadcaster.subscribe(CONSTANTS.EVENT.CONNECTION_LOST, handleConnectionLost);
    globalBroadcaster.subscribe(CONSTANTS.EVENT.TOKEN_AUTH_STARTED, onTokenAuth, 10);
    globalBroadcaster.subscribe(CONSTANTS.EVENT.TOKEN_NOT_FOUND, onTokenOrSessionError);
    globalBroadcaster.subscribe(CONSTANTS.EVENT.SESSION_EXPIRED, onTokenOrSessionError);

    if (__testonly__) { this.getWebSocket = function() { return webSocket; }; }
    if (__testonly__) { this.webSocketConnect = webSocketConnect; }
    if (__testonly__) { this.websocketDisconnect = websocketDisconnect; }
    if (__testonly__) { this.WEBSOCKET_CONSTANTS = WEBSOCKET_CONSTANTS; }
    if (__testonly__) { this.setNotifier = function(data) { notifier = data; }; }
};
var notificationManager = new NotificationManager();
fcs.notification = notificationManager;

/**
* Groups presence related resources (Presence Update, Presence Watcher)
*
* @name presence
* @namespace
* @memberOf fcs
*
* @version 3.0.4
* @since 3.0.0
*/
var Presence = function() {

   /**
    * States for presences update requests.
    *
    * @name State
    * @enum {number}
    * @since 3.0.0
    * @readonly
    * @memberOf fcs.presence
    * @property {number} [CONNECTED=0] The user is currently online
    * @property {number} [UNAVAILABLE=1] The user is currently unavailable
    * @property {number} [AWAY=2] The user is currently away
    * @property {number} [OUT_TO_LUNCH=3] The user is currently out for lunch
    * @property {number} [BUSY=4] The user is currently busy
    * @property {number} [ON_VACATION=5] The user is currently on vacation
    * @property {number} [BE_RIGHT_BACK=6] The user will be right back
    * @property {number} [ON_THE_PHONE=7] The user is on the phone
    * @property {number} [ACTIVE=8] The user is currently active
    * @property {number} [INACTIVE=9] The user is currently inactive
    * @property {number} [PENDING=10] Waiting for user authorization
    * @property {number} [OFFLINE=11] The user is currently offline
    * @property {number} [CONNECTEDNOTE=12] The user is connected and defined a note
    * @property {number} [UNAVAILABLENOTE=13] The user is unavailable and defined a note
    */
    this.State = {
        CONNECTED:       0,
        UNAVAILABLE:     1,
        AWAY:            2,
        OUT_TO_LUNCH:    3,
        BUSY:            4,
        ON_VACATION:     5,
        BE_RIGHT_BACK:   6,
        ON_THE_PHONE:    7,
        ACTIVE:          8,
        INACTIVE:        9,
        PENDING:         10,
        OFFLINE:         11,
        CONNECTEDNOTE:   12,
        UNAVAILABLENOTE: 13
    };

   /**
    * Sends the user's updated status and activity to the server.
    *
    * @name fcs.presence.update
    * @function
    * @param {fcs.presence.State} presenceState The user's presence state
    * @param {function} onSuccess The onSuccess() callback to be called
    * @param {function} onFailure The onFailure({@link fcs.Errors}) callback to be called
    * @since 3.0.0
    * @example
    * var onSuccess = function(){
    *    //do something here
    * };
    * var onError = function (err) {
    *   //do something here
    * };
    *
    * fcs.presence.update(fcs.presence.State.BE_RIGHT_BACK, onSuccess, onError );
    */

   /**
    * Returns the last watched user list
    *
    * @name fcs.presence.getLastWatchedUserList
    * @function
    * @since 3.0.0
    */

   /**
     * Stops the presence watch refresh timer
     *
     * @name fcs.presence.stopPresenceWatchRefreshTimer
     * @function
     * @since 3.0.0
     */

   /**
    * Starts watching the presence status of users in the provided user list.
    *
    * @name fcs.presence.watch
    * @function
    * @param {Array.<String>} watchedUserList list of users whose status is to be watched
    * @param {function} onSuccess The onSuccess() callback to be called
    * @param {function} onFailure The onFailure({@link fcs.Errors}) callback to be called
    * @since 3.0.0
    * @example
    * var onSuccess = function(){
    *    //do something here
    * };
    * var onError = function (err) {
    *   //do something here
    * };
    *
    * fcs.presence.watch(["user1", "user2"], onSuccess, onError );
    */

   /**
    * Stops watching the presence status of the users in the provided user list.
    *
    * @name fcs.presence.stopwatch
    * @function
    * @param {Array.<String>} unwatchedUserList list of users whose status is to be unwatched
    * @param {function} onSuccess The onSuccess() callback to be called
    * @param {function} onFailure The onFailure({@link fcs.Errors}) callback to be called
    * @since 3.0.0
    * @example
    * var onSuccess = function(){
    *    //do something here
    * };
    * var onError = function (err) {
    *   //do something here
    * };
    *
    * fcs.presence.stopwatch(["user1", "user2"], onSuccess, onError );
    */

   /**
    * Sends a request to receive a notification for the presence status of the users in the provided user list.<br />
    * For each user in the provided list, {@link fcs.presence.event:onReceived} handler will be invoked.
    *
    * @name fcs.presence.retrieve
    * @function
    * @param {Array.<String>} userList list of users whose status is to be retrieved
    * @param {function} onSuccess The onSuccess() callback to be called
    * @param {function} onFailure The onFailure({@link fcs.Errors}) callback to be called
    * @since 3.0.0
    * @example
    * var onSuccess = function(){
    *    //do something here
    * };
    * var onError = function (err) {
    *   //do something here
    * };
    *
    * fcs.presence.retrieve(["user1", "user2"], onSuccess, onError );
    */

   /**
    * Handler called for when receiving a presence notification
    *
    * @name onReceived
    * @event
    * @memberOf fcs.presence
    * @param {fcs.presence.UpdateEvent} event The presence update event
    * @since 3.0.0
    * @example
    *
    * fcs.presence.onReceived = function(data) {
    *    //do something here
    * }
    */


   /**
    * Represents a presence change event
    *
    * @name UpdateEvent
    * @class
    * @memberOf fcs.presence
    * @version 3.0.4
    * @since 3.0.0
    */
   this.UpdateEvent = function(){};
   /**
    * User name of the contact whose presence has changed.
    *
    * @name fcs.presence.UpdateEvent#name
    * @field
    * @type {String}
    * @since 3.0.0
    */

    /**
     * The presence state of the user.
     *
    * @name fcs.presence.UpdateEvent#state
    * @field
    * @type {fcs.presence.State}
    * @since 3.0.0
    */

   /**
    * The type of network for this presence.
    *
    * @name fcs.presence.UpdateEvent#type
    * @field
    * @type {String}
    * @since 3.0.0
    */
};
var PRESENCE_URL = "/presence", PRESENCE_WATCHER_URL = "/presenceWatcher",
    REQUEST_TYPE_WATCH = "watch", REQUEST_TYPE_STOP_WATCH = "stopwatch", REQUEST_TYPE_GET = "get",
    presence = new Presence(),
    PRESENCE_STATE = presence.State,
    STATUS_OPEN = "open",
    STATUS_CLOSED = "closed",
    ACTIVITY_UNKNOWN = "unknown",
    ACTIVITY_AWAY = "away",
    ACTIVITY_LUNCH = "lunch",
    ACTIVITY_BUSY = "busy",
    ACTIVITY_VACATION = "vacation",
    ACTIVITY_ON_THE_PHONE = "on-the-phone",
    ACTIVITY_OTHER = "other",
    NOTE_BE_RIGHT_BACK = "Be Right Back",
    NOTE_OFFLINE = "Offline",
    USERINPUT_ACTIVE = "active",
    USERINPUT_INACTIVE = "inactive";

var PresenceStateParser =  function(){

    var stateRequest = [];

    stateRequest[PRESENCE_STATE.CONNECTED] = {status: STATUS_OPEN, activity: ACTIVITY_UNKNOWN};
    stateRequest[PRESENCE_STATE.UNAVAILABLE] = {status: STATUS_CLOSED, activity: ACTIVITY_UNKNOWN};
    stateRequest[PRESENCE_STATE.AWAY] = {status: STATUS_OPEN, activity: ACTIVITY_AWAY};
    stateRequest[PRESENCE_STATE.OUT_TO_LUNCH] = {status: STATUS_OPEN, activity: ACTIVITY_LUNCH};
    stateRequest[PRESENCE_STATE.BUSY] = {status: STATUS_CLOSED, activity: ACTIVITY_BUSY};
    stateRequest[PRESENCE_STATE.ON_VACATION] = {status: STATUS_CLOSED, activity: ACTIVITY_VACATION};
    stateRequest[PRESENCE_STATE.BE_RIGHT_BACK] = {status: STATUS_OPEN, activity: ACTIVITY_OTHER, note: NOTE_BE_RIGHT_BACK};
    stateRequest[PRESENCE_STATE.ON_THE_PHONE] = {status: STATUS_OPEN, activity: ACTIVITY_ON_THE_PHONE};
    stateRequest[PRESENCE_STATE.ACTIVE] = {status: STATUS_OPEN, activity: ACTIVITY_UNKNOWN, userInput: USERINPUT_ACTIVE};
    stateRequest[PRESENCE_STATE.INACTIVE] = {status: STATUS_CLOSED, activity: ACTIVITY_UNKNOWN, userInput: USERINPUT_INACTIVE};
    stateRequest[PRESENCE_STATE.OFFLINE] = {status: STATUS_CLOSED, activity: ACTIVITY_OTHER, note: NOTE_OFFLINE};
    stateRequest[PRESENCE_STATE.CONNECTEDNOTE] = {status: STATUS_OPEN, activity: ACTIVITY_OTHER};
    stateRequest[PRESENCE_STATE.UNAVAILABLENOTE] = {status: STATUS_CLOSED, activity: ACTIVITY_OTHER};

    this.getRequestObject = function(presenceState){
        var state = stateRequest[presenceState];

        if(state){
            return state;
        } else {
        throw new Error("Invalid Presence State");
        }
    };

    this.getState = function(presence) {
        switch (presence.userInput) {
            case USERINPUT_ACTIVE:
                return PRESENCE_STATE.ACTIVE;
            case USERINPUT_INACTIVE:
                return PRESENCE_STATE.INACTIVE;
        }

        switch (presence.note) {
            case NOTE_BE_RIGHT_BACK:
                return PRESENCE_STATE.BE_RIGHT_BACK;
            case NOTE_OFFLINE:
                return PRESENCE_STATE.OFFLINE;
        }
        if (presence.note) {
            if (presence.status === STATUS_OPEN) {
                return PRESENCE_STATE.CONNECTEDNOTE;
            }
            else {
                return PRESENCE_STATE.UNAVAILABLENOTE;
            }
        }

        switch (presence.activity) {
            case ACTIVITY_AWAY:
                return PRESENCE_STATE.AWAY;
            case ACTIVITY_LUNCH:
                return PRESENCE_STATE.OUT_TO_LUNCH;
            case ACTIVITY_BUSY:
                return PRESENCE_STATE.BUSY;
            case ACTIVITY_VACATION:
                return PRESENCE_STATE.ON_VACATION;
            case ACTIVITY_ON_THE_PHONE:
                return PRESENCE_STATE.ON_THE_PHONE;
            case ACTIVITY_UNKNOWN:
                if (presence.status === STATUS_OPEN) {
                    return PRESENCE_STATE.CONNECTED;
                }
                else {
                    return PRESENCE_STATE.UNAVAILABLE;
                }
        }
        return PRESENCE_STATE.CONNECTED;
    };
};

var presenceStateParser;

var PresenceImpl = function() {
    var lastWatchedUserList = null, subscriptionRefreshTimer = null,
            onPresenceWatchSuccess = null, onPresenceWatchFailure = null,
            logger = logManager.getLogger("presenceService"),
            subscriptionExpiryTimestamp = 0;


    this.getLastWatchedUserList = function () {
        return lastWatchedUserList;
    };

    this.onReceived = null;

    this.update = function(presenceState, onSuccess, onFailure) {

        server.sendPostRequest({
            "url": getWAMUrl(1, PRESENCE_URL),
            "data": {"presenceRequest": presenceStateParser.getRequestObject(presenceState)}
                },
                onSuccess,
                onFailure
        );

    };

    function makeRequest(watchedUserList, onSuccess, onFailure, action) {
        var data = {"presenceWatcherRequest":{"userList": watchedUserList, "action": action}};
        server.sendPostRequest({
                        "url": getWAMUrl(1, PRESENCE_WATCHER_URL),
                        "data": data
                    },
                    onSuccess,
                    onFailure
        );
    }

    function stopSubscriptionRefreshTimer() {
        if (subscriptionRefreshTimer) {
            logger.trace("presence watch timer is stopped: " + subscriptionRefreshTimer);
            clearTimeout(subscriptionRefreshTimer);
            subscriptionRefreshTimer = null;
        }
    }

    function startServiceSubscription(watchedUserList, onSuccess, onFailure) {
        var self = this, currentTimestamp = utils.getTimestamp();

        if (!watchedUserList) {
            if (lastWatchedUserList) {
                logger.trace("watchedUserList is empty, use lastWatchedUserList.");
                watchedUserList = lastWatchedUserList;
            }
            else {
                logger.trace("presence service subscription has not been initialized, do not trigger service subscription.");
                return;
            }
        }

        logger.info("presence service subscription, currentTimestamp: " + currentTimestamp + " expiryTimestamp: " + subscriptionExpiryTimestamp);
        if (currentTimestamp - subscriptionExpiryTimestamp < 0) {
            logger.trace("previous presence service subscription is still valid, do not trigger service subscription.");
            return;
        }

        if (onSuccess) {
            onPresenceWatchSuccess = onSuccess;
        }
        if (onFailure) {
            onPresenceWatchFailure = onFailure;
        }

        logger.info("subscribe presence status of users:", watchedUserList);
        makeRequest(watchedUserList, function(result) {
            var response, expiry;
            if (result) {
                response = result.presenceWatcherResponse;
                if (response) {
                    expiry = response.expiryValue / 2;
                    if (expiry) {
                        subscriptionExpiryTimestamp = utils.getTimestamp() + expiry * 1000;
                        stopSubscriptionRefreshTimer();
                        subscriptionRefreshTimer = setTimeout(function() {
                            self.watch(watchedUserList, null, onPresenceWatchFailure);
                        }, expiry * 1000);
                        logger.trace("presence watch, timer: " + subscriptionRefreshTimer + " expiryTimestamp: " + subscriptionExpiryTimestamp);
                    }
                }
            }
            lastWatchedUserList = watchedUserList;
            if (onPresenceWatchSuccess && typeof onPresenceWatchSuccess === 'function') {
                onPresenceWatchSuccess(result);
            }
        }, onPresenceWatchFailure, REQUEST_TYPE_WATCH);
    }

    this.watch = startServiceSubscription;

    this.stopwatch = function(watchedUserList, onSuccess, onFailure) {

        makeRequest(watchedUserList, onSuccess, onFailure, REQUEST_TYPE_STOP_WATCH);
    };


    this.retrieve = function(watchedUserList, onSuccess, onFailure) {

        makeRequest(watchedUserList, onSuccess, onFailure, REQUEST_TYPE_GET);
    };

    function presenceServiceOnSubscriptionStartedHandler() {
        startServiceSubscription(undefined, onPresenceWatchSuccess, onPresenceWatchFailure);
    }

    globalBroadcaster.subscribe(CONSTANTS.EVENT.DEVICE_SUBSCRIPTION_STARTED,
            presenceServiceOnSubscriptionStartedHandler);

    globalBroadcaster.subscribe(CONSTANTS.EVENT.DEVICE_SUBSCRIPTION_ENDED,
            stopSubscriptionRefreshTimer);

};

PresenceImpl.prototype = new Presence();
var presenceService = new PresenceImpl();
fcs.presence = presenceService;

presenceStateParser = new PresenceStateParser();

/*
 * In order to find the users presence client receives 3 parameters from WAM
 * status, activity, note and userInput.
 * status is received in every presence notification and can have two parameters: open and closed
 * For activity and note there can be only one of them in the presence notification.
 * userInput comes with activity but userInput is the  one that decides presence.
 * Presence is decided according to status and activity/note combination
 */
NotificationCallBacks.presenceWatcher = function(data){
    if(!fcs.notification.isAnonymous()) {
        var presence = new fcs.presence.UpdateEvent(), presenceParams = data.presenceWatcherNotificationParams;

        presence.name = utils.getProperty(presenceParams, 'name');
        presence.type = utils.getProperty(presenceParams, 'type');
        presence.status = utils.getProperty(presenceParams, 'status');
        presence.activity = utils.getProperty(presenceParams, 'activity');
        presence.note = utils.getProperty(presenceParams, 'note');
        presence.userInput = utils.getProperty(presenceParams, 'userInput');

        presence.state = presenceStateParser.getState(presence);

        utils.callFunctionIfExist(fcs.presence.onReceived, presence);

    }
};
// Return the fcs module.
return fcs;

}));


var utils = (function() {
    var exports = {};

    exports.createUUIDv4 = function() {
        var s = [],
            itoh = '0123456789ABCDEF';

        // Make array of random hex digits. The UUID only has 32 digits in it, but we
        // allocate an extra items to make room for the '-'s we'll be inserting.
        for (var i = 0; i < 36; i++) {
            s[i] = Math.floor(Math.random() * 0x10);
        }

        // Conform to RFC-4122, section 4.4
        s[14] = 4; // Set 4 high bits of time_high field to version
        s[19] = (s[19] & 0x3) | 0x8; // Specify 2 high bits of clock sequence

        // Convert to hex chars
        for (i = 0; i < 36; i++) {
            s[i] = itoh[s[i]];
        }

        // Insert '-'s
        s[8] = s[13] = s[18] = s[23] = '-';

        return s.join('');
    };

    exports.extend = function(out) {
        out = out || {};

        for (var i = 1; i < arguments.length; i++) {
            if (!arguments[i]) {
                continue;
            }

            for (var key in arguments[i]) {
                if (arguments[i].hasOwnProperty(key)) {
                    out[key] = arguments[i][key];
                }
            }
        }

        return out;
    };

    exports.defaults = function(out) {
        out = out || {};

        for (var i = 1; i < arguments.length; i++) {
            if (!arguments[i]) {
                continue;
            }

            for (var key in arguments[i]) {
                if (!out[key] && arguments[i].hasOwnProperty(key)) {
                    out[key] = arguments[i][key];
                }
            }
        }

        return out;
    };

    // TODO: Document and test
    exports.param = function(object) {
        var encodedString = '', prop;

        for (prop in object) {
            if (object.hasOwnProperty(prop)) {
                var value = object[prop];

                if (value === undefined) {
                    // Skip over values that are undefined
                    continue;
                }

                if (value === null) {
                    value = '';
                }

                if (typeof value !== 'string') {
                    value = JSON.stringify(value);
                }

                if (encodedString.length > 0) {
                    encodedString += '&';
                }
                encodedString += encodeURIComponent(prop) + '=' + encodeURIComponent(value);
            }
        }
        return encodedString;
    };

    return exports;
})();


// Not sure about this pattern.
var request = (function(utils) {

    var exports = function (options) {

        options = utils.defaults(options, exports.defaultOptions);
        options.headers = utils.defaults(options.headers, exports.defaultHeaders);

        // Take the data parameters and append them to the URL.
        var queryString = utils.param(options.params);
        if (queryString.length > 0) {
            if (options.url.indexOf('?') === -1) {
                options.url += '?';
            }
            options.url += queryString;
        }

        var xhr = new XMLHttpRequest();
        xhr.open(options.type, options.url, true);
        xhr.withCredentials = options.withCredentials;

        // Set the headers.
        var headerKey;
        for (headerKey in options.headers) {
            xhr.setRequestHeader(headerKey, options.headers[headerKey]);
        }

        // Stringify data if not already a string.
        if (options.data && typeof options.data !== 'string' ) {
            options.data = JSON.stringify(options.data);
        }

        // Attach the call back
        xhr.onreadystatechange = function() {
            if (xhr.readyState === 4) {

                // All the status codes considered a success.
                var success = (xhr.status >= 200 && xhr.status < 300) || xhr.status === 304;

                // TODO: Promisify this.
                if (success) {
                    if (typeof options.success === 'function') {
                        var response = xhr.responseText;
                        if (options.dataType === 'json' && typeof response === 'string') {

                            if (response.length) {
                                response = JSON.parse(response);
                            } else {
                                response = {};
                            }
                        }

                        options.success({status: xhr.status, response: response});
                    }
                } else {
                    if (typeof options.failure === 'function') {
                        options.failure({status: xhr.status, statusText: xhr.statusText, response: xhr.responseText });
                    }
                }

            } else if (xhr.readyState === 0) {
                if (typeof options.failure === 'function') {
                    options.failure({status: xhr.status, statusText: xhr.statusText, response: 'Call aborted.'});
                }
            }
        };

        xhr.send(options.data);
    };

    exports.defaultHeaders = {
        'Content-Type': 'application/json',
        'Accept': 'application/json'
    };

    exports.defaultOptions = {
        type: 'GET',
        url: '',
        withCredentials: false,
        dataType: 'json'
    };

    return exports;

})(utils);

// Local variable reference to FCS.
var fcs = this.fcs;

// private copy of response codes
var responseCodes = {
    OK: 0,
    internalServerError: 1,
    tokenExpired: 10,
    permissionDenied: 11,
    usageQuotaExceeded: 12,
    insufficientFunds: 13,
    validationFailed: 14,
    missingParameter: 15,
    invalidParameterValue: 16,
    badParameterValue: 17,
    unknownRequest: 18,
    noData: 19,
    alreadyExists: 50,
    invalidIdentifier: 51,
    invalidPassword: 52,
    doesNotExist: 53,
    invalidCountryCode: 54,
    invalidCredentials: 55,
    ajaxError: 5000,
    wsError: 6000,
    wsAlreadyOpened: 6001,
    wsNotFound: 6002,
    wsCreateError: 6003,
    wsNotAuth: 6004
};

var api = {
    /**
     * Version of this release
     * @type String
     */
    version: kandyVersion,
    // public copy of response codes
    responseCodes: JSON.parse(JSON.stringify(responseCodes))
};

var _nofunc = function(){};
var _logger = {
        'info': _nofunc,
        'warn': _nofunc,
        'error': _nofunc,
        'debug': _nofunc
    };

function _setLogLevel(level){

    var lError = false, lWarn = false, lInfo = false, lDebug = false;
    if(window.console && console.warn && console.error && console.info){
        if(level === 'debug'){
            lError = lWarn = lInfo = lDebug = true;
        }if(level === 'info'){
            lError = lWarn = lInfo = true;
        } else if(level === 'warn'){
            lError = lWarn = true;
        } else if(level === 'error'){
            lError = true;
        }

        if(lDebug){
            _logger.debug = window.console.log.bind(window.console, 'kandy debug: %s');
        }

        if(lInfo){
            _logger.info = window.console.info.bind(window.console, 'kandy info: %s');
        }

        if(lWarn){
            _logger.warn = window.console.warn.bind(window.console, 'kandy warn: %s');
        }

        if(lError){
            _logger.error = window.console.error.bind(window.console, 'kandy error: %s');
        }
    }
}

//default log level
_setLogLevel('warn');

var _events = {};


_events = {};

/**
 * @event callinitiated
 * Fired when an outgoing call is initiated
 * @param {Call} fcs.call.OutgoingCall object
 * @param {String} number ID of the callee
 */
_events.callinitiated = null;

/**
 * @event callinitiatefailed
 * Fired when an attempt to initiate an outgoing call fails
 * @param {String} reasonText The reason for the failure or empty string
 */
_events.callinitiatefailed = null;

/**
 * @event callincoming
 * Fired when a call is coming in
 * @param {Call} call The call object
 */
_events.callincoming = null;

/**
 * @event callended
 * Fired when a call has ended
 * @param {string} call The call object
 */
_events.callended = null;

/**
 * @event callendfailed
 * Fired when a call fails to end
 * @param {string} call The call object
 */
_events.callendfailed = null;

/**
 * @event callanswered
 * Fired when a call is answered
 * @param {Call} call The call object
 * @param {Boolean} isAnonymous True if the all is anonymous
 */
_events.callanswered = null;

/**
 * @event callanswerfailed
 * Fired when a failure occurs when answering a call
 * @param {Call} call The call object
 */
_events.callanswerfailed = null;

/**
 * @event oncall
 * Fired while on call
 * @param {Call} call The call object
 */
_events.oncall = null;

/**
 * @event callstatechanged
 * Fired during a call when the state of the call changes. For example whether
 * the other side is no longer sending video.
 * @param {Call} call The call object
 */
_events.callstatechanged = null;


_events.media = null;


/**
 * @event presencenotification
 * @param {String} username Username of presence event
 * @param {String} state Presence state
 * @param {String} description Presence description
 * @param {String} activity Presence activity
 * Fired when presence notification is received
 */
_events.presencenotification = null;

/**
 * @event loginsuccess
 * @depracated
 * Fired when logged on
 */
_events.loginsuccess = null;

/**
 * @event setupsuccess
 * Fired when logged on
 */
_events.setupsuccess = null;

/**
 * @event setupfailed
 * Fired when a login attempt fails
 */
_events.setupfailed = null;

/**
 * @event loginfailed
 * @depracated
 * Fired when logged on
 */
_events.loginfailed = null;

/**
 * @event callrejected
 * Fired when a call is rejected
 * @param {Call} call The call object
 */
_events.callrejected = null;

/**
 * @event callrejectfailed
 * Fired when a call rejection fails
 * @param {Call} call The call object
 */
_events.callrejectfailed = null;

/**
 * @event callignored
 * Fired when a call ignore succeeds
 * @param {Call} call The call object
 */
_events.callignored = null;

/**
 * @event callignorefailed
 * Fired when a call ignore fails
 * @param {Call} call The call object
 */
_events.callignorefailed = null;

/**
 * @event remotehold
 * Fired other party puts call on hold
 * @param {Call} call The call object
 */
_events.remotehold = null;

/**
 * @event remoteunhold
 * Fired other party releases hold on call
 * @param {Call} call The call object
 */
_events.remoteunhold = null;

/**
 * @event onconnectionlost
 * Fired when connection to comms server dies
 */
_events.onconnectionlost = null;

/**
 * @event onmessagesavailable
 * Fired when new messages available
 */
_events.messagesavailable = null;

/**
 * @method _fireEvent
 * Fires passed event
 * @private
 */
function _fireEvent() {
    var eventName = Array.prototype.shift.apply(arguments);

    if (_events[eventName]) {
        _events[eventName].apply(null, arguments);
    }
}

/**
 * @property {Object} _config Configuration for KandyAPI.Phone.
 * @private
 */
var _config = {
    listeners: {},
    kandyApiUrl: 'https://api.kandy.io/v1.2',
    mediatorUrl: 'http://service.kandy.io:8080/kandywrapper-1.0-SNAPSHOT',
    messageProvider: 'fring',
    pstnOutNumber: '71',
    sipOutNumber: '72',
    allowAutoLogin: false,
    kandyWSUrl: null,
    fcsConfig: {
        restPlatform: 'kandy', // 'spidr' or 'kandy'
        kandyApiUrl: 'https://api.kandy.io/v1.1/users/gateway',
        useInternalJquery: false
    },
    spidrApi: {
        cors: true,
        disableNotifications: null,
        notificationType: fcs.notification.NotificationTypes.WEBSOCKET,
        useInternalJquery: false,
        websocketProtocol: 'wss'
    },
    spidrMedia: {
      pluginMode: 'auto',
      pluginLogLevel: 2,
      screenSharing: false
    }
};

/**
 * @property {String} _userDetails. User Details gotten from login
 * @private
 */
var _userDetails = null;

/**
 * @property {Boolean} _autoReconnect. Auto Reconnection configuration
 * @private
 */

var _autoReconnect = true;

/**
 * @property {Boolean} _registerForCalls. Register for Calls configuration
 * @private
 */

var _registerForCalls = true;

/**
 * this method is for setting up default values for an ajax call
 * @param options = {
 * type: 'GET',
 * url: 'http://localhost/api',
 * data: {foo: 'bar'},
 * contentType: 'application/json'
 * acceptType: 'application/json'
 * success: function(response){...},
 * failure: function(){...}
 * }
 * @private
 */
var _kandyRequest = function (options) {

    // set the default method as GET
    if (options.type === undefined || !options.type) {
        options.type = 'GET';
    }

    // Set the base url to talk to the correct version of kandy.
    options.url = (options.kandyApiUrl || _config.kandyApiUrl) + options.url;

    // Add an empty params option if there is none so we can add the key.
    options.params = options.params || {};

    // check if the url doesn't contain 'key' as param, then add userDetails.userAccessToken as 'key'
    if (!options.params.key) {
        options.params.key = _userDetails.userAccessToken;
    }

    // The REST API will expect a body if Content-Type is not set to 'text/html' during a DELETE operation.
    if (options.type === 'DELETE' && !options.data) {
        options.headers = options.headers || {};
        options.headers['Content-Type'] = 'text/html';
    }

    var success = options.success;
    var failure = options.failure;

    // Map a different success function that also takes into account the response's status field.
    // Note: Doing this will be more elegant once we have promise support.
    options.success = function(result) {
        if (result.response.status === responseCodes.OK) {
            if (success) {
                // Note: Here we just send the response back to the success handler to support backwards compatibility.
                success(result.response);
            }
        } else {
            if (failure) {
                failure(result.statusText, responseCodes.ajaxError);
            }
        }
    };

    options.failure = function(result) {
        // TODO: These error messages seem arbitrary and rather useless. Remove them?
        if (result.status === 403 || result.status === 401) {
            console.log('Unauthorized Error !!!');
        } else if (result.status === 426) {
            console.log('Kandy upgrade required!');
        }

        if (failure) {
            failure(result.statusText, responseCodes.ajaxError);
        }
    };

    request(options);
};

var _initLogger = function () {
    try {
        fcs.logManager.initLogging(function (x, y, z) {
            if (z.message === 'ERROR') {
                window.console.log(z.message);
            }
            else {
                window.console.log(z.message);
            }
        }, true);
        _logger = fcs.logManager.getLogger('kandy_js');
    } catch (e) {
        // TODO: Shouldn't swallow exceptions silently
    }
};

//=================================================================
//=======================  WebSocket  =============================
//=================================================================

/**
 * @type Object Registered WebSocket events
 * @private
 */
var _wsEvents = {};

/**
 * @type Object Registered WebSocket handlers for responses
 * @private
 */
var _wsResponses = {};

/**
 * @type WebSocket WebSocket object
 * @private
 */
var _ws = null;

/**
 * @type Timeout Timeout for ping mechanism
 * @private
 */
var _wsPingTimeout;

var _connectionLostTimeout;

var _reconnectCount = 0;

var _onlineEventAttached = false;


/**
 * @method isWebSocketOpened
 * @return {Boolean} indication wether is the WebSocket is opened
 * @private
 */
function isWebSocketOpened() {
    var opened = false;

    if (_ws) {
        opened = (_ws.readyState === 1);
    }

    return opened;
}



function sendWSPing() {
    if (isWebSocketOpened())
    {
        _wsPingTimeout = setTimeout(sendWSPing, 30000);

        var json = {
           'message_type': 'ping'
        };
        try {
            _ws.send(JSON.stringify(json));
        } catch (e) {
            window.console.error('Exception in sendWSPing: ' + e.message);
        }
    }
}

function reconnect() {
    window.console.log('reconnecting');

    openWebSocket(function () {
        window.console.log('reconnect success');
        _reconnectCount = 0;
        _fireEvent('onconnectionrestored');
    },
            function () {
                _reconnectCount++;
                window.console.log('failed to reconnect');
                autoReconnect();
            });
}

function autoReconnect() {
    var timeout = (_reconnectCount > 10) ? ((_reconnectCount > 100) ? 60000 : 30000) : 10000;
    _connectionLostTimeout = setTimeout(reconnect, timeout);
}

function onBrowserOnline() {
    window.console.log('browser going online');
    clearTimeout(_connectionLostTimeout);
    _connectionLostTimeout = setTimeout(reconnect, 500);
}

function onBrowserOffline() {
    window.console.log('browser going offline');
    clearTimeout(_wsPingTimeout);
    _ws.close();
}

function buildWebSocketUrlFromDataChannelConfig(dataChannelConfig) {
    var host = dataChannelConfig.data_server_host,
            port = dataChannelConfig.data_server_port,
            isSecure = dataChannelConfig.is_secure;

    //only keep the url because of an issue with REST api 1.1 and 1.2
    var hostMatches = host.match('^(?:https?:\/\/)?(?:www\.)?([^\/]+)');
    var portString = port ? (':' + port) : '';

    return (isSecure ? 'wss' : 'ws') + '://' + hostMatches[1] + portString;
}

/**
 * @method sendWebSocketData
 * Send data through the WebSocket Channel
 * @param {Object} [success] The success callback
 * @param {Object} [failure] The failure callback.
 * @private
 */
function openWebSocket(success, failure) {
    var handshareId;

    if (isWebSocketOpened()) {
        closeWebSocket();
        return;
    }

    window.KandyAPI.getDataChannelConfiguration(
            function (result) {
                _config.kandyWSUrl = buildWebSocketUrlFromDataChannelConfig(result) + '?client_sw_type=js&client_sw_version=' + api.version + '&user_access_token=';

                try {
                    _logger.debug('Opening websocket, UAT = ' + _userDetails.userAccessToken);
                    _ws = new WebSocket(_config.kandyWSUrl + encodeURIComponent(_userDetails.userAccessToken));

                } catch (wsError) {
                    if (failure) {
                        failure('Error opening websocket', responseCodes.wsCreateError);
                    }
                    return;
                }

                if (_ws !== null && _ws.readyState !== 2 && _ws.readyState !== 3) {

                    _ws.onopen = function (evt) {
                        if (window.addEventListener && !_onlineEventAttached) {
                            window.addEventListener('online', onBrowserOnline);
                            window.addEventListener('offline', onBrowserOffline);
                            _onlineEventAttached = true;
                        }
                        success();
                        sendWSPing();
                    };

                    _ws.onclose = function (evt) {
                        if(_wsPingTimeout){
                            if (_autoReconnect && !_connectionLostTimeout) {
                                window.console.log('connection closed');
                                clearTimeout(_wsPingTimeout);
                                autoReconnect();
                            }

                            if (_reconnectCount === 0) {
                                _fireEvent('onconnectionlost', evt);
                            }
                        }
                    };

                    _ws.onerror = function (evt) {
                        _fireEvent('onconnectionerror', evt);
                    };

                    _ws.onmessage = function (evt) {
                        var message = JSON.parse(evt.data), callbacks, responseCallbacks, callbackItter, callbackLength;
                        if (message.message_type === 'response') {
                            responseCallbacks = _wsResponses[message.id];
                            if (responseCallbacks) {
                                delete _wsResponses[message.id];
                                if (message.status === 0) {
                                    if (responseCallbacks.success) {
                                        responseCallbacks.success();
                                    }
                                }
                                else {
                                    if (responseCallbacks.failure) {
                                        responseCallbacks.failure(message.message, message.status);
                                    }
                                }
                            }
                        } else {
                            if (_wsEvents.hasOwnProperty(message.message_type)) {
                                callbacks = _wsEvents[message.message_type];

                                if (callbacks && callbacks.length > 0) {
                                    callbackLength = callbacks.length;
                                    for (callbackItter = 0; callbackItter < callbackLength; callbackItter++) {
                                        if (typeof callbacks[callbackItter] === 'function') {
                                            callbacks[callbackItter](message);
                                        }
                                    }

                                }
                            }
                        }
                    };
                } else {
                    failure('Error opening websocket', responseCodes.wsCreateError);
                }
            },
            failure
            );
}

/**
 * @method sendWebSocketData
 * Send data through the WebSocket Channel
 * @param {String} data
 * @param {Object} [success] The success callback
 * @param {Object} [failure] The failure callback.
 * @private
 */
function sendWebSocketData(data, success, failure) {
    if (isWebSocketOpened()) {
        if ((success || failure) && (data.id === undefined)) {
            var id = utils.createUUIDv4();
            data.id = id;
            _wsResponses[id] = {success: success, failure: failure};
        }

        try {
            _ws.send(JSON.stringify(data));
        } catch (e) {
            window.console.log('Exception in sendWebSocketData: ' + e.message);
        }

    } else {
        failure();
    }
}

/**
 * @method closeWebSocket
 * Close the Notification Web Socket
 * @private
 */
function closeWebSocket() {
    clearTimeout(_wsPingTimeout);
    _wsPingTimeout = null;
    if (isWebSocketOpened()) {
        _ws.close();
    }
}

/**
 * @method registerWebSocketListeners
 * Register listeners for Web Socket Events
 * @param {Object} listeners
 * @private
 */
function registerWebSocketListeners(listeners) {
    var listner;
    if (listeners) {
        for (var listener in listeners) {
            if (listeners.hasOwnProperty(listener)) {
                if (_wsEvents[listener] === undefined) {
                    _wsEvents[listener] = [];
                }
                _wsEvents[listener].push(listeners[listener]);
            }
        }
    }
}


//=================================================================
//====================  Exposed Methods  ==========================
//=================================================================

/**
 * @method setup
 * Setup the API
 * @param {Object} config Configuration.
 */
api.setup = function (config) {
    // setup default configuration
    _config = utils.extend(_config, config);

    // setup listeners
    if (config.hasOwnProperty('listeners')) {
        for (var listener in config.listeners) {
            _events[listener] = config.listeners[listener];
        }
    }

    if (config.hasOwnProperty('autoreconnect')) {
        _autoReconnect = config.autoreconnect;
    }

    if (config.hasOwnProperty('registerforcalls')) {
        _registerForCalls = config.registerforcalls;
    }


    if (config.hasOwnProperty('loglevel')) {
        _setLogLevel(config.loglevel);
    }

    if(_registerForCalls && _setupCall){
        _setupCall(config);
    }

    if(config.hasOwnProperty('exposeFcs')) {
        api._fcs = fcs;
    }
};


function _getUserAccessToken (domainApiKey, username, userPassword, success, failure, options) {
    // if username has domain in it remove it
    username = username.split('@')[0];

    _kandyRequest({
        url: '/domains/users/accesstokens',
        params: {
            key: domainApiKey,
            'user_id': username,
            'user_password': userPassword,
            'client_sw_version': options.client_sw_version,
            'client_sw_type': options.client_sw_type,
            'kandy_device_id': options.kandy_device_id
        },
        success: function (response) {
            if (success) {
                success(response.result);
            }
        },
        failure: failure
    });
}

/**
 * @method getUserAccessToken
 * Retrieves a user access token
 * @param {String} domainApiKey
 * @param {String} userName
 * @param {String} userPassword
 * @param {Function} success The success callback.
 * @param {Function} failure The failure callback.
 * @param {client_sw_version: '2.1.0', client_sw_type: 'JS/android/ios', kandy_device_id: YOUR_DEVICE_ID}
 */
api.getUserAccessToken = _getUserAccessToken;

/**
 * @method getLimitedUserDetails
 * Retrieves details about a user
 * @param {String} userAccessToken
 * @param {Function} success The success callback.
 * @param {Function} failure The failure callback.
 */
api.getLimitedUserDetails = function (userAccessToken, success, failure) {
    _kandyRequest({
        url: '/users/details/limited',
        params: {
            key: userAccessToken
        },
        success: function (response) {
            if (success) {
                success(response.result.user);
            }
        },
        failure: failure
    });
};

/**
 * @method getLimitedDomainDetails
 * Retrieves details about a domain
 * @param {String} domainAccessToken
 * @param {Function} success The success callback.
 * @param {Function} failure The failure callback.
 */
api.getLimitedDomainDetails = function (domainAccessToken, success, failure) {
    _kandyRequest({
        url: '/domains/details/limited',
        params: {
            key: domainAccessToken
        },
        success: function (response) {
            if (success) {
                success(response.result);
            }
        },
        failure: failure
    });
};

/**
 * @method getDevices
 * Retrieves devices for users
 * @param {Function} userAccessToken User Access Token.
 * @param {Function} success The success callback.
 * @param {Function} failure The failure callback.
 */
api.getDevices = function (userAccessToken, success, failure) {
    _kandyRequest({
        url: '/users/devices',
        params: {
            key: userAccessToken
        },
        success: function (response) {
            if (success) {
                success(response.result);
            }
        },
        failure: failure
    });
};


/**
 * @method getLastSeen
 * get last seen time stamps for the users passed in
 * @param {Array of String} users
 * @param {Function} success The success callback.
 * @param {Function} failure The failure callback.
 */
api.getLastSeen = function (users, success, failure) {

    _kandyRequest({
        url: '/users/presence/last_seen',
        params: {
            users: users
        },
        success: function (response) {
            if (success) {
                success(response.result);
            }
        },
        failure: failure
    });
};


/**
 * @method getDataChannelConfiguration
 * get the data channel configuration used to connect to the websocket
 * @param {Function} success The success callback.
 * @param {Function} failure The failure callback.
 */
api.getDataChannelConfiguration = function (success, failure) {
    _kandyRequest({
        url: '/users/configurations/data_channel',
        success: function (response) {
            if (success) {
                success(response.result);
            }
        },
        failure: failure
    });
};

/**
 * @method getAnonymousUser
 * Get an anonymous user
 * @param {String} domainAccessToken Domain access token
 */
api.getAnonymousUser = function (domainAccessToken, success, failure) {
    _kandyRequest({
        url: '/domains/access_token/users/user/anonymous',
        params: {
            key: domainAccessToken
        },
        success: function (response) {
            if (success) {
                success(response.result);
            }
        },
        failure: failure
    });
};

/**
 * @method login
 * Login as a user
 * @param {String} domainApiKey
 * @param {String} userName
 * @param {String} userPassword
 * @param {Function} success The success callback.
 * @param {Function} failure The failure callback.
 *
 *
 */
api.login = function (domainApiKey, userName, password, success, failure) {

    var failureFunction = function () {
        _userDetails = null;
        if(failure && typeof failure === 'function'){
            failure();
        }
    };

    // TODO: Rename these to camel case
    var options = {
        'client_sw_version': api.version,
        'client_sw_type': 'JS',
        'kandy_device_id': null
    };

    _getUserAccessToken(domainApiKey, userName, password,
            function (result) {
                var userAccessToken = result.user_access_token;

                api.getLimitedUserDetails(userAccessToken,
                        function (userDetailResult) {
                            _userDetails = userDetailResult;
                            _userDetails.userPassword = password;
                            _userDetails.userAccessToken = userAccessToken;
                            openWebSocket(
                                    //openWebSocket Success
                                    function () {
                                        _userDetails.devices = [];
                                        api.getDevices(userAccessToken,
                                            function (data) {
                                                _userDetails.devices = data.devices;

                                                if(_registerForCalls && _logInToSpidr){
                                                    _logInToSpidr(function(){
                                                            if(success){
                                                                success(result);
                                                            }
                                                        },
                                                        failureFunction
                                                    );
                                                } else {
                                                    if(success){
                                                        success(result);
                                                    }
                                                }
                                            },
                                            failureFunction
                                        );
                                    },
                                    failureFunction
                                    );
                        },
                        failureFunction
                        );
            },
            failureFunction,
            options
            );

};

/**
 * @method loginSSO
 * Log in with user access token (for single sign-on)
 * @param {String} userAccessToken User access token
 * @param {Function} [success] The success callback.
 * @param {Function} [failure] The failure callback.
 * @param {String} [password] The user password.
 */
api.loginSSO = function (userAccessToken, success, failure, password) {
    _logger.info('loginSSO is not supported for calls at the moment, unless provided with the password');

    var failureFunction = function () {
        _userDetails = null;
        if(failure && typeof failure === 'function'){
            failure();
        }
    };

    api.getLimitedUserDetails(userAccessToken,
        function (result) {
            _userDetails = result;
            _userDetails.userAccessToken = userAccessToken;
            _userDetails.userPassword = password;
            openWebSocket(
                    function () {
                        _userDetails.devices = [];
                        api.getDevices(userAccessToken,
                            function (data) {
                                _userDetails.devices = data.devices;

                                if(_registerForCalls && _logInToSpidr){
                                    _logInToSpidr(function(){
                                            if(success){
                                                success(result);
                                            }
                                        },
                                        failureFunction
                                    );
                                } else {
                                    if(success){
                                        success(result);
                                    }
                                }
                            },
                            failureFunction
                        );
                    },
                    failureFunction);
        },
        failureFunction
    );


};

api.logout = function (success) {
    closeWebSocket();
    _logOutOfSpidr(success);
};

api.reconnect = function (success, failure) {
    openWebSocket(success, failure);
};


//=================================================================
//========================  SESSION  ==============================
//=================================================================
api.Session = api.session = (function () {
    var me = {};

    var _listeners = {
    };

    // forward messages to the appropriate session handler
    var _messageHandler = function (message) {
        var simpleType, sessionListeners, sessionListener, listenerCount, listenerItter = 0;

        if (message.message_type === 'sessionNotification') {
            message = message.payload;
        }

        window.console.log('Session message recvd: ' + message.message_type);
        simpleType = message.message_type.replace(/^session/, 'on');
        sessionListeners = _listeners[message.session_id];

        if (sessionListeners) {
            var listnerCount = sessionListeners.length;

            for (listenerItter; listenerItter < listnerCount; listenerItter++) {
                sessionListener = sessionListeners[listenerItter];
                if (sessionListener && sessionListener.hasOwnProperty(simpleType)) {
                    try {
                        sessionListener[simpleType](message);
                    } catch (e) {
                        console.log('could not execute listner: ' + e);
                    }
                }
            }
        }
    };

    registerWebSocketListeners({
        'sessionData': _messageHandler,
        'sessionNotification': _messageHandler
    });


    /**
     * @method setListeners
     * Create a session
     * @param {String} sessionId
     * @param {Object} listeners
     * @param {Function} success Function called when create session succeeds, takes one parameter, sessionId
     * @param {Function} failure Function called when create session fails, takes two parameters: errorMessage, errorCode
     *
     * Example listeners:
     *      {
     *          'onData': onSessionData,
     *          'onActive': onSessionStarted,
     *          'onUserJoinRequest': onSessionUserJoinRequest,
     *          'onUserJoin': onSessionUserJoinRequest,
     *          'onJoinApprove': onSessionJoinApprove,
     *          'onJoinReject': onSessionJoinReject,
     *          'onUserLeave': onSessionUserLeave,
     *          'onUserBoot': onSessionUserBoot,
     *          'onBoot': onSessionBoot,
     *          'onInactive': onSessionEnded,
     *          'onTerminated': onSessionTerminated
     *       }
     */
    me.setListeners = function (sessionId, listeners) {

        if (_listeners[sessionId] === undefined) {
            _listeners[sessionId] = [];
        }

        _listeners[sessionId].push(listeners);
    };


    /**
     * @method create
     * Create a session
     * @param {Object} sessionConfig Contains session_type, session_name, session_description, user_nickname, user_first_name, user_last_name, user_phone_number, user_email
     * @param {Function} success Function called when create session succeeds, takes one parameter, sessionId
     * @param {Function} failure Function called when create session fails, takes two parameters: errorMessage, errorCode
     *
     * Example sessionConfig:
     *   {
     *       session_type: 'support',
     *       session_name: sessionName,
     *       session_description: "Jim's Support Session",
     *       user_nickname: "User 1",
     *       user_first_name: "User",
     *       user_last_name: "One",
     *       user_phone_number: "303-555-1212",
     *       user_email: "user1@gmailicon.com"
     *   }
     */
    me.create = function (sessionConfig, success, failure) {
        _kandyRequest({
            type: 'POST',
            url: '/users/sessions/session',
            data: sessionConfig,
            success: function (response) {
                if (success) {
                    success(response.result);
                }
            },
            failure: failure
        });
    };


    me.activate = function (sessionId, success, failure) {
        _kandyRequest({
            type: 'POST',
            url: '/users/sessions/session/id/start',
            data: {
                'session_id': sessionId
            },
            success: function (response) {
                if (success) {
                    success();
                }
            },
            failure: failure
        });
    };

    me.inactivate = function (sessionId, success, failure) {
        _kandyRequest({
            type: 'POST',
            url: '/users/sessions/session/id/stop',
            data: {
                'session_id': sessionId
            },
            success: function (response) {
                if (success) {
                    success();
                }
            },
            failure: failure
        });
    };

    /**
     * @method sendData
     * Send data to session participants
     * @param {String} sessionId Id of session to send data to
     * @param {Object} data Data to be sent to the session participants
     * @param {function} [success] success callback
     * @param {function} [failure] failure callback
     * @param {String} [destination] full user id for the destination (if none provided, sends to all participants)
     */
    me.sendData = function (sessionId, data, success, failure, destination) {
        sendWebSocketData({
            'message_type': 'sessionData',
            'session_id': sessionId,
            destination: destination,
            payload: data
        }, success, failure);
    };

    /**
     * @method terminate
     * Delete a session
     * @param {String} sessionId Id of session to delete
     */
    me.terminate = function (sessionId, success, failure) {
        _kandyRequest({
            type: 'DELETE',
            url: '/users/sessions/session/id',
            data: {
                'session_id': sessionId
            },
            success: function (response) {
                if (success) {
                    success();
                }
            },
            failure: failure
        });
    };

    /**
     * @method getSessionInfoById
     * Get session info by session ID
     * @param {String} sessionId Id of session
     */
    me.getInfoById = function (sessionId, success, failure) {
        _kandyRequest({
            url: '/users/sessions/session/id',
            params: {
                'session_id': sessionId
            },
            success: function (response) {
                if (success) {
                    success(response.result);
                }
            },
            failure: failure
        });
    };

    /**
     * @method getSessionInfoByName
     * Get session info by Name
     * @param {String} sessionName Name of session
     */
    me.getInfoByName = function (sessionName, success, failure) {
        _kandyRequest({
            url: '/users/sessions/session/name',
            params: {
                'session_name': sessionName
            },
            success: function (response) {
                if (success) {
                    success(response.result);
                }
            },
            failure: failure
        });
    };

    /**
     * @method getOpenSessions
     * Get open sessions
     */
    me.getOpenSessions = function (success, failure) {

        _kandyRequest({
            url: '/users/sessions',
            success: function (response) {
                if (success) {
                    success(response.result);
                }
            },
            failure: failure
        });
    };


    /**
     * @method getOpenSessionsByType
     * Get open sessions
     */
    me.getOpenSessionsByType = function (sessionType, success, failure) {
        _kandyRequest({
            url: '/users/sessions',
            params: {
                'session_type': sessionType
            },
            success: function (response) {
                if (success) {
                    success(response.result);
                }
            },
            failure: failure
        });
    };

    /**
     * @method getOpenSessionsCreatedByUser
     * Get open sessions created by this user
     */
    me.getOpenSessionsCreatedByUser = function (success, failure) {
        _kandyRequest({
            url: '/users/sessions/user',
            success: function (response) {
                if (success) {
                    success(response.result);
                }
            },
            failure: failure
        });
    };


    /**
     * @method joinSessionBy
     * Request to join a session by ID
     * @param {String} joinConfig Reason why we are leaving the session
     * @param {Function} [success] Function called when leaving succeeds
     * @param {Function} [failure] Function called when leaving fails
     */
    me.join = function (sessionId, joinConfig, success, failure) {
        _kandyRequest({
            type: 'POST',
            url: '/users/sessions/session/id/participants/participant',
            data: {
                'session_id': sessionId
            },
            success: function (response) {
                if (success) {
                    success(response.result);
                }
            },
            failure: failure
        });
    };

    /**
     * @method leave
     * Leave a session by session ID
     * @param {String} sessionId Session ID
     * @param {String} [leaveReason] Reason why we are leaving the session
     * @param {Function} [success] Function called when leaving succeeds
     * @param {Function} [failure] Function called when leaving fails
     */
    me.leave = function (sessionId, leaveReason, success, failure) {
        _kandyRequest({
            type: 'DELETE',
            url: '/users/sessions/session/id/participants/participant',
            data: {
                'session_id': sessionId,
                'leave_reason': leaveReason
            },
            success: function (response) {
                if (success) {
                    success();
                }
            },
            failure: failure
        });
    };


    /**
     * @method acceptJoinRequest
     * Admin accepts join request
     * @param {String} sessionId Session ID
     * @param {String} fullUserId Full user ID
     * @param {Function} success Function called when create session succeeds
     * @param {Function} failure Function called when create session fails
     */
    me.acceptJoinRequest = function (sessionId, fullUserId, success, failure) {

        _kandyRequest({
            type: 'POST',
            url: '/users/sessions/session/id/admin/participants/participant/join',
            data: {
                'session_id': sessionId,
                'full_user_id': fullUserId
            },
            success: function (response) {
                if (success) {
                    success();
                }
            },
            failure: failure
        });
    };

    /**
     * @method rejectJoinRequest
     * Admin rejects join request
     * @param {String} sessionId Session ID
     * @param {String} fullUserId Full user ID
     * @param {String} rejectReason Reason for rejecting the user
     * @param {Function} success Function called when create session succeeds
     * @param {Function} failure Function called when create session fails
     */
    me.rejectJoinRequest = function (sessionId, fullUserId, rejectReason, success, failure) {
        _kandyRequest({
            type: 'DELETE',
            url: '/users/sessions/session/id/admin/participants/participant/join',
            data: {
                'session_id': sessionId,
                'full_user_id': fullUserId,
                'reject_reason': rejectReason
            },
            success: function (response) {
                if (success) {
                    success();
                }
            },
            failure: failure
        });
    };

    /**
     * @method bootUser
     * Admin boots a user from a session
     * @param {String} sessionId Session ID
     * @param {String} fullUserId Full user ID
     * @param {String} bootReason Reason for booting the user
     * @param {Function} success Function called when create session succeeds
     * @param {Function} failure Function called when create session fails
     */
    me.bootUser = function (sessionId, fullUserId, bootReason, success, failure) {

        _kandyRequest({
            type: 'DELETE',
            url: '/users/sessions/session/id/admin/participants/participant',
            data: {
                'session_id': sessionId,
                'full_user_id': fullUserId,
                'boot_reason': bootReason
            },
            success: function (response) {
                if (success) {
                    success();
                }
            },
            failure: failure
        });
    };

    return me;
}());

//=================================================================
//========================  MESSAGING  ============================
//=================================================================
api.messaging = (function () {

    /**
     * @property {Object} _imContentTypes Holds IM content types.
     * @private
     */
    var _imContentTypes = {
        VIDEO: 'video',
        AUDIO: 'audio',
        IMAGE: 'image',
        FILE: 'file',
        LOCATION: 'location',
        CONTACT: 'contact'
    };

    var me = {};

    function _sendIM(destination, contentType, msg, success, failure, isGroup, messageOptions) {

        // Create the message object.
        var uuid = (messageOptions && messageOptions.uuid) || utils.createUUIDv4();
        var message = {
            message: {
                contentType: contentType,
                UUID: uuid,
                message: msg
            }
        };

        // Select the correct url and params depending on whether this is a group IM or not.
        var url;
        var params;
        if(isGroup){
            utils.extend(message.message, {
                'group_id': destination
            });
            url = '/users/chatgroups/chatgroup/messages';
            //message.messageType = "groupChat";
        } else {
            message.message.destination = destination;
            message.messageType = 'chat';
            url = '/devices/messages';
            params = {
                'device_id': _userDetails.devices[0].id
            };
        }

        _kandyRequest({
            type: 'POST',
            url: url,
            params: params,
            data: message,
            success: function (response) {
                if (success) {
                    success(message.message);
                }
            },
            failure: failure
        });
        return uuid;
    }

    /**
     * @method _sendImWithAttachment
     * @param {String} destination Destination of message recipient
     * @param {Object} attachment Attachement to be sent
     * @param {String} contentType Content Type of file.
     * @param {Function} success The success callback.
     * @param {Function} failure The failure callback.
     * Sends a File message to another Kandy user
     */
    function _sendImWithAttachment(destination, attachment, contentType, success, failure, isGroup, messageOptions) {
        if (_config.messageProvider === 'fring') {

            var uuid = utils.createUUIDv4();
            messageOptions = messageOptions || {};

            // Upload file and if we get a success send the IM
            me.uploadFile(attachment, function (fileUuid) {

                var message = {
                    mimeType: attachment.type,
                    'content_uuid': fileUuid,
                    'content_name': attachment.name
                };
                if (messageOptions) {
                    Object.keys(messageOptions).forEach(function(key) {
                        message[key] = messageOptions[key];
                    });
                }
                return _sendIM(destination, contentType, message, success, failure, isGroup, {uuid: uuid});

            }, failure);
            return uuid;
        } else {
            _logger.error('NOT SUPPORTED');
            if(failure){
                failure();
            }
        }
    }

    function _sendImWithLocation(destination, location, success, failure, isGroup) {

        return _sendIM(destination, _imContentTypes.LOCATION, {
            mimeType: 'location/utm',
            'media_map_zoom': 10,
            'location_latitude': location.location_latitude,
            'location_longitude': location.location_longitude
        }, success, failure, isGroup);

    }

    function _sendJSON(user, object, success, failure, isGroup) {
        return _sendIM(user, 'text', {
            mimeType: 'application/json',
            json: JSON.stringify(object)
        }, success, failure, isGroup);
    }

    /**
     * @method sendSMS
     * @param {String} phone number.
     * @param {String} sender number.
     * @param {String} sms text.
     * @param {Function} success The success callback.
     * @param {Function} failure The failure callback.
     * Retrieves address book entries.
     */
    me.sendSMS = function (number, sender, text, success, failure) {
        _kandyRequest({
            type: 'POST',
            url: '/devices/smss',
            params: {
                'device_id': _userDetails.devices[0].id
            },
            data: {
                message: {
                    source: sender,
                    destination: number,
                    message: {text: text}
                }
            },

            // TODO: Shouldn't we map to return result here?
            success: success,
            failure: failure
        });
    };

    /**
     * @method sendIm
     * @param {String} user Username of message recipient
     * @param {String} text Textual message to be sent to recipient
     * @param {Function} success The success callback.
     * @param {Function} failure The failure callback.
     * Sends a textual instant message to another Kandy user
     */
    me.sendIm = function (user, text, success, failure) {
        if (_config.messageProvider === 'fring') {
            return _sendIM(user, 'text', { 'mimeType': 'text/plain', 'text': text }, success, failure, false);
        } else if (_config.messageProvider === 'spidr') {
            var im = new fcs.im.Message();
            im.primaryContact = user;
            im.type = 'A2';
            im.msgText = text;
            im.charset = 'UTF-8';

            fcs.im.send(im, success, failure);
            return 0;
        }
    };

    me.sendJSON = function (user, object, success, failure) {
        return _sendJSON(user, object, success, failure);
    };

    /**
     * @method sendImWithFile
     * @param {String} user Username of message recipient
     * @param {Object} file File to be sent
     * @param {Function} success The success callback.
     * @param {Function} failure The failure callback.
     * Sends a File message to another Kandy user
     */
    me.sendImWithFile = function (user, file, success, failure) {
        return _sendImWithAttachment(user, file, _imContentTypes.FILE, success, failure);
    };

    /**
     * @method sendImWithImage
     * @param {String} user Username of message recipient
     * @param {Object} file File to be sent
     * @param {Function} success The success callback.
     * @param {Function} failure The failure callback.
     * Sends a File message to another Kandy user
     */
    me.sendImWithImage = function (user, file, success, failure) {
        return _sendImWithAttachment(user, file, _imContentTypes.IMAGE, success, failure);
    };

    /**
     * @method sendImWithAudio
     * @param {String} user Username of message recipient
     * @param {Object} file File to be sent
     * @param {Function} success The success callback.
     * @param {Function} failure The failure callback.
     * Sends a File message to another Kandy user
     */
    me.sendImWithAudio = function (user, file, success, failure) {
        return _sendImWithAttachment(user, file, _imContentTypes.AUDIO, success, failure);
    };

    /**
     * @method sendImWithVideo
     * @param {String} user Username of message recipient
     * @param {Object} file File to be sent
     * @param {Function} success The success callback.
     * @param {Function} failure The failure callback.
     * Sends a File message to another Kandy user
     */
    me.sendImWithVideo = function (user, file, success, failure) {
        return _sendImWithAttachment(user, file, _imContentTypes.VIDEO, success, failure);
    };

    me.sendImWithContact = function (user, vCard, success, failure, displayName) {
        return _sendImWithAttachment(user, vCard, _imContentTypes.CONTACT, success, failure, null, {'contact_display_name': displayName});
    };

    //TODO TEST
    me.sendImWithLocation = function (user, location, success, failure) {
        return _sendImWithLocation(user, location, success, failure);
    };

    /**
     * @method uploadFile
     * @param {File} file File to be sent
     * @param {Function} success The success callback.
     * @param {UUID} success.uuid The UUID of the uploaded file.
     * @param {Function} failure The failure callback.
     * @param {string}    failure.message Error Message.
     * @param {string}    failure.statusCode Error status code.
     * Uploads file to be used in Rich IM messaging
     */
    me.uploadFile = function (file, success, failure) {
        // Generate a UUID
        var uuid = utils.createUUIDv4();

        // Create a new FormData object.
        var formData = new FormData();

        // Add the file to the request.
        formData.append('file', file, file.name);

        // Set up the request.
        var xhr = new XMLHttpRequest();

        var url = _config.kandyApiUrl + '/devices/content?key=' + _userDetails.userAccessToken + '&content_uuid=' + encodeURIComponent(uuid) + '&device_id=' + _userDetails.devices[0].id + '&content_type=' + encodeURIComponent(file.type);

        // Open the connection.
        xhr.open('POST', url, true);

        // Set up a handler for when the request finishes.
        xhr.onload = function () {
            if (xhr.status === 200) {
                var result = JSON.parse(xhr.responseText);

                if (result.status === responseCodes.OK) {
                    // File(s) uploaded.
                    if (success) {
                        success(uuid);
                    }
                }
                else if (failure) {
                    failure(result.message, result.status);
                }

            } else {
                if (failure) {
                    failure('Request Error', '500');
                }
            }
        };

        // Send the Data.
        xhr.send(formData);

        return uuid;
    };

    /**
     * @method buildFileUrl
     * @param {uuid} UUID for file
     * Builds Url to uploaded file
     */
    me.buildFileUrl = function (uuid) {
        return _config.kandyApiUrl + '/devices/content?key=' + _userDetails.userAccessToken + '&content_uuid=' + encodeURIComponent(uuid) + '&device_id=' + _userDetails.devices[0].id;
    };

    /**
     * @method buildFileThumbnailUrl
     * @param {uuid} UUID for file
     * @param {string} size of thumbnail 24x24
     * Builds Url to thumbnail uploaded file
     */
    me.buildFileThumbnailUrl = function (uuid, size) {
        if (size === undefined || !size) {
            size = '500x500';
        }

        return _config.kandyApiUrl + '/devices/content/thumbnail?key=' + _userDetails.userAccessToken + '&content_uuid=' + encodeURIComponent(uuid) + '&device_id=' + _userDetails.devices[0].id + '&thumbnail_size=' + size;
    };

    /**
     * @method getIm
     * Retrieves IM messages
     * @param {Function} success The success callback.
     * @param {Function} failure The failure callback.
     * @return {Object} response An array of messages
     * e.g.
     * {
     *    [
     *      {
     "messageType":"chat",
     "sender":
     {
     "user_id":"972542205056",
     "domain_name":"domain.com",
     "full_user_id":"972542205056@domain.com"
     },
     "UUID":"acd2fa752c3c4edf97de8b0a48f622f0",
     "timestamp":"1400510413",
     "message":
     {
     "mimeType": "text/plain",
     "text": "let's meet tonight"
     }
     }
     *    ]
     * }
     */
    me.getIm = function (success, failure, autoClear) {

        _logger.info('Consider using the message event instead of fetching messages');

        if (autoClear === undefined) {
            autoClear = true;
        }

        _kandyRequest({
            url: '/devices/messages',
            params: {
                'device_id': _userDetails.devices[0].id
            },
            success: function (response) {
                var incoming;
                if (success) {

                    if (response.result.messages.length) {
                        // prepare id list for clearing
                        var idList = response.result.messages.map(function (item) {
                            return item.UUID;
                        });

                        // make sure UUIDs have hyphens
                        response.result.messages = response.result.messages.map(function (msg) {
                            if (msg.UUID.indexOf('-') === -1) {
                                msg.UUID = [msg.UUID.substring(0, 8),
                                    msg.UUID.substring(8, 12),
                                    msg.UUID.substring(12, 16),
                                    msg.UUID.substring(16, 20),
                                    msg.UUID.substring(20, msg.UUID.length)
                                ].join('-');
                            }
                            return msg;
                        });
                    }

                    success(response.result);

                    if (autoClear && response.result.messages.length) {
                        me.clearIm(idList);
                    }
                }
            },
            failure: failure
        });
    };

    /**
     * @method clearIm
     * Retrieves IM messages
     * @param {Array} ids Id of IMs to remove.
     * @param {Function} failure The failure callback.
     * @return {Object} response An array of messages
     */
    me.clearIm = function (ids, success, failure) {
        var i = 0;
        for (; i < ids.length; i += 10) {
            // TODO: Once we have promises we should handle the success and failure callbacks properly.
            _kandyRequest({
                type: 'DELETE',
                url: '/devices/messages',
                params: {
                    messages: ids.slice(i, i + 10),
                    'device_id': _userDetails.devices[0].id
                },
                failure: failure
            });
        }
    };

    me.getGroups = function (success, failure){
        _kandyRequest({
            url: '/users/chatgroups',
            success: function (response) {
                if (success) {
                    success(response.result);
                }
            },
            failure: failure
        });
    };

    me.createGroup = function (name, image, success, failure){
        //TODO what should be the image.

        var data = {
            'group_name': name,
            'group_image': {}
        };

        _kandyRequest({
            type: 'POST',
            data: data,
            url: '/users/chatgroups',
            success: function (response) {
                if (success) {
                    success(response.result);
                }
            },
            failure: failure
        });
    };

    me.getGroupById = function (id, success, failure){
        _kandyRequest({
            url: '/users/chatgroups/chatgroup',
            params: {
                'group_id': id
            },
            success: function (response) {
                if (success) {
                    success(response.result);
                }
            },
            failure: failure
        });
    };

    me.deleteGroup = function (id, success, failure){
        _kandyRequest({
            type: 'DELETE',
            url: '/users/chatgroups/chatgroup',
            params: {
                'group_id': id
            },
            success: function (response) {
                if (success) {
                    success(response.result);
                }
            },
            failure: failure
        });
    };

    me.updateGroup = function (id, name, image, success, failure){

        var data = {
            'group_id': id,
            'group_name': name,
            'group_image': {}
        };

        _kandyRequest({
            type: 'PUT',
            data: data,
            url: '/users/chatgroups/chatgroup',
            success: function (response) {
                if (success) {
                    success(response.result);
                }
            },
            failure: failure
        });
    };

    me.addGroupMembers = function (id, members, success, failure){
        var data = {
            members: members
        };
        _kandyRequest({
            type: 'POST',
            url: '/users/chatgroups/chatgroup/members',
            params: {
                'group_id': id
            },
            data: data,
            success: function (response) {
                if (success) {
                    success(response.result);
                }
            },
            failure: failure
        });
    };

    me.removeGroupMembers = function (id, members, success, failure){
        _kandyRequest({
            type: 'DELETE',
            url: '/users/chatgroups/chatgroup/members',
            params: {
                'group_id': id,
                members: members
            },
            success: function (response) {
                if (success) {
                    success(response.result);
                }
            },
            failure: failure
        });
    };

    me.leaveGroup = function (id, success, failure){
        _kandyRequest({
            type: 'DELETE',
            url: '/users/chatgroups/chatgroup/members/membership',
            params: {
                'group_id': id
            },
            success: function (response) {
                if (success) {
                    success(response.result);
                }
            },
            failure: failure
        });
    };

    function muteUnmuteGroup(id, success, failure, mute){
        _kandyRequest({
            type: 'PUT',
            url: '/users/chatgroups/chatgroup/mute',
            params: {
                mute: mute,
                'group_id': id
            },
            success: function (response) {
                if (success) {
                    success(response.result);
                }
            },
            failure: failure
        });
    }

    me.muteGroup = function (id, success, failure){
        muteUnmuteGroup(id, success, failure, true);
    };

    me.unmuteGroup = function (id, success, failure){
        muteUnmuteGroup(id, success, failure, false);
    };

    function muteUnmuteGroupMembers(id, members, success, failure, mute){

        var data = {
            members: members,
            mute: mute,
            'group_id': id
        };

        _kandyRequest({
            type: 'PUT',
            data: data,
            url: '/users/chatgroups/chatgroup/members/mute',
            success: function (response) {
                if (success) {
                    success(response.result);
                }
            },
            failure: failure
        });
    }

    me.muteGroupMember = function (id, members, success, failure){
        muteUnmuteGroupMembers(id, members, success, failure, true);
    };

    me.unmuteGroupMember = function (id, members, success, failure){
        muteUnmuteGroupMembers(id, members, success, failure, false);
    };

    me.sendGroupIm = function (groupId, text, success, failure) {
        return _sendIM(groupId, 'text', { mimeType: 'text/plain', text: text }, success, failure, true);
    };

    /**
     * @method sendGroupImWithFile
     * @param {String} user Username of message recipient
     * @param {Object} file File to be sent
     * @param {Function} success The success callback.
     * @param {Function} failure The failure callback.
     * Sends a File message to another Kandy user
     */
    me.sendGroupImWithFile = function (user, file, success, failure) {
        return _sendImWithAttachment(user, file, _imContentTypes.FILE, success, failure, true);
    };

    /**
     * @method sendGroupImWithImage
     * @param {String} user Username of message recipient
     * @param {Object} file File to be sent
     * @param {Function} success The success callback.
     * @param {Function} failure The failure callback.
     * Sends a File message to another Kandy user
     */
    me.sendGroupImWithImage = function (user, file, success, failure) {
        return _sendImWithAttachment(user, file, _imContentTypes.IMAGE, success, failure, true);
    };

    /**
     * @method sendGroupImWithAudio
     * @param {String} user Username of message recipient
     * @param {Object} file File to be sent
     * @param {Function} success The success callback.
     * @param {Function} failure The failure callback.
     * Sends a File message to another Kandy user
     */
    me.sendGroupImWithAudio = function (user, file, success, failure) {
        return _sendImWithAttachment(user, file, _imContentTypes.AUDIO, success, failure, true);
    };

    /**
     * @method sendGroupImWithVideo
     * @param {String} user Username of message recipient
     * @param {Object} file File to be sent
     * @param {Function} success The success callback.
     * @param {Function} failure The failure callback.
     * Sends a File message to another Kandy user
     */
    me.sendGroupImWithVideo = function (user, file, success, failure) {
        return _sendImWithAttachment(user, file, _imContentTypes.VIDEO, success, failure, true);
    };

    me.sendGroupJSON = function (user, object, success, failure) {
        return _sendJSON(user, object, success, failure, true);
    };

    me.sendGroupImWithLocation = function (user, location, success, failure) {
        return _sendImWithLocation(user, location, success, failure, true);
    };

    function _notificationHandler(message) {
        var msg = message.message;
        if(msg){
            var msgType = msg.messageType;
            if (msgType === 'chat') {
                _fireEvent('message', msg);
            } else if (msgType === 'groupChat') {
                _fireEvent('chatGroupMessage', msg);
            } else if (msgType === 'chatGroupInvite') {
                _fireEvent('chatGroupInvite', msg);
            } else if (msgType === 'chatGroupBoot') {
                _fireEvent('chatGroupBoot', msg);
            } else if (msgType === 'chatGroupLeave') {
                _fireEvent('chatGroupLeave', msg);
            } else if (msgType === 'chatGroupUpdate') {
                _fireEvent('chatGroupUpdate', msg);
            } else if (msgType === 'chatGroupDelete') {
                _fireEvent('chatGroupDelete', msg);
            }
        }
    }

    registerWebSocketListeners({
        'notification': _notificationHandler
    });

    return me;
}());



//=================================================================
//=========================== PHONE ===============================
//=================================================================
/**
 * @author Russell Holmes
 * KandyAPI.Phone
 * @singleton
 * The Kandy Phone is used to make calls (audio and video), get presence notifications, and send IMs.
 */

var _logInToSpidr;
var _logOutOfSpidr;
var _setupCall;

api.Phone = api.call = api.voice = (function () {
    var me = {};

    /**
     * @property {String} _domainApiKey Domain API Key token.
     * @private
     */
    var _domainApiKey = null;

    /**
     * @property {Object} _callTypes Holds call types.
     * @private
     */
    var _callTypes = {
        INCOMING_CALL: 1,
        OUTGOING_CALL: 2
    };

    /**
     * @property {Object} _presenceTypes Types of presence.
     * @private
     */
    var _presenceTypes = {
        0: 'Available',
        1: 'Unavailable',
        2: 'Away',
        3: 'Out To Lunch',
        4: 'Busy',
        5: 'On Vacation',
        6: 'Be Right Back',
        7: 'On The Phone',
        8: 'Active',
        9: 'Inactive',
        10: 'Pending',
        11: 'Offline'
    };

    /**
     * @property {CallObject} _calls call objects.
     * @private
     */
    var _calls = [];

    var _mediaInitiated = false;

    var _callStates = null;

    var _initMediaDone = false;

    me.MediaErrors = fcs.call.MediaErrors;

    /**
     * @method _startIntraFrame
     * Starts infra-frame coding for compression
     * @param {Object} call The call Object
     * @private
     */
    function _startIntraFrame(call) {
        call.intraframe = setInterval(function () {
            if (call) {
                call.sendIntraFrame();
            } else {
                _stopIntraFrame(call);
            }
        }, 5000);
    }

    /**
     * @method _stopIntraFrame
     * Stops infra-frame coding for compression
     * @private
     */
    function _stopIntraFrame(call) {
        if (call.intraframe) {
            clearInterval(call.intraframe);
        }
    }


    /**
     * @method _handleCallNotification
     * Handles incoming call notifications
     * @param {Call} call The call object
     * @private
     */
    function _handleCallNotification(call) {
        _calls[call.getId()] = call;
        // check if this is an anonymous call
        call.isAnonymous = (call.callerNumber.indexOf('concierge') !== -1);
        _fireEvent('callincoming', call, call.isAnonymous);
    }

    /**
     * @method _handleIncomingCallStateChange
     * Handles incoming call state changes
     * @param {Call} call The call object
     * @param {State} state The state of the call
     * @private
     */
    function _handleIncomingCallStateChange(call, state) {
        var callId = call.getId(),
                holdState;

        call.isIncoming = true;
        call.isOutgoing = false;
        var localCall = _calls[callId];

        if (!localCall) {
            _calls[callId] = localCall = call;
        }

        holdState = call.getHoldState();

        if (holdState === 'REMOTE_HOLD') {
            _logger.info('CALL HELD REMOTELY');
            call.remoteHold = true;
            _fireEvent('remotehold', call);
        } else {
            if (call.remoteHold !== undefined && call.remoteHold) {
                _logger.info('CALL REMOTE HOLD RELEASED');
                _fireEvent('remoteunhold', call);
            }
            call.remoteHold = false;
        }

        if (state === _callStates.IN_CALL) {
            if (holdState === 'LOCAL_HOLD') {
                _logger.info('ON HOLD');
            } else {
                _logger.info('ON CALL');
            }

            if (call.canSendVideo()) {
                _startIntraFrame(localCall);
            }
        } else if (state === _callStates.RENEGOTIATION) {
            _fireEvent('callstatechanged', call);
        } else if (state === _callStates.ON_HOLD) {
            _logger.info('CALL HELD REMOTELY');
        } else if (state === _callStates.RINGING) {
            _logger.info('RINGING');
            _fireEvent('ringing', call.getId());
        } else if (state === _callStates.ENDED) {
            if (call) {
                _stopIntraFrame(localCall);
                if (call.statusCode === 0 || call.statusCode === undefined) {
                    _logger.info('CALL END');
                } else {
                    if ((call.statusCode >= 100 && call.statusCode <= 300)) {
                        _logger.error('WebRTC ERROR');
                    } else {
                        _logger.error('ERROR');
                    }
                }
                delete _calls[callId];
                _fireEvent('callended', call);
            }
        } else if (state === _callStates.REJECTED) {
            _logger.info('REJECTED');
        } else if (state === _callStates.OUTGOING) {
            _logger.info('DIALING');
        } else if (state === _callStates.INCOMING) {
            _logger.info('INCOMING');
        //} else if (state === _callStates.JOINED) {
        // TODO: Log something?
        }
    }

    /**
     * @method _handleOutgoingCallStateChange
     * Handles outgoing call state changes
     * @param {Call} call The call object
     * @param {State} state The state of the call
     * @private
     */
    function _handleOutgoingCallStateChange(call, state) {

        var callId = call.getId(),
                holdState;

        var localCall = _calls[callId];
        localCall.isOutgoing = true;
        localCall.isIncoming = false;

        holdState = call.getHoldState();
        if (holdState === 'REMOTE_HOLD') {
            _logger.info('CALL HELD REMOTELY');
            call.remoteHold = true;
            _fireEvent('remotehold', call);
        } else {
            if (call.remoteHold !== undefined && call.remoteHold) {
                _logger.info('CALL REMOTE HOLD RELEASED');
                _fireEvent('remoteunhold', call);
            }
            call.remoteHold = false;
        }


        if (state === _callStates.IN_CALL) {
            if (holdState === 'LOCAL_HOLD') {
                _logger.info('ON HOLD');
            } else {
                _logger.info('ON CALL');
            }

            if (call.canSendVideo()) {
                _startIntraFrame(localCall);
            }
            _fireEvent('oncall', call);
        } else if (state === _callStates.RENEGOTIATION) {
            _fireEvent('callstatechanged', call);
        } else if (state === _callStates.ON_HOLD) {
            _logger.info('CALL HELD REMOTELY');
        } else if (state === _callStates.RINGING) {
            _logger.info('RINGING');
            _fireEvent('ringing', call.getId());
        } else if (state === _callStates.ENDED) {
            if (call) {
                _stopIntraFrame(localCall);
                if (call.statusCode === 0 || call.statusCode === undefined) {
                    _logger.info('CALL END');
                } else {
                    if ((call.statusCode >= 100 && call.statusCode <= 300)) {
                        _logger.error('WebRTC ERROR');
                    } else {
                        _logger.error('ERROR');
                    }
                }

                if (localCall.isAnonymous && localCall.isOutgoing) {
                    me.logout();
                }

                delete _calls[callId];
                _fireEvent('callended', call);

            }
        } else if (state === _callStates.REJECTED) {
            _logger.info('REJECTED');
        } else if (state === _callStates.OUTGOING) {
            _logger.info('DIALING');
        } else if (state === _callStates.INCOMING) {
            _logger.info('INCOMING');
        } else if (state === _callStates.JOINED) {
            _logger.info('JOINED');
        }
    }

    /**
     * @method _handlePresenceNotification
     * Handles presence notifications, fires the presencenotification event
     * @param {Presence} presence The Presence object
     * @private
     */
    function _handlePresenceNotification(presence) {
        if (presence.state === null) {
            _logger.info('State is empty.');
            return;
        }

        if (presence.name === null) {
            _logger.info('Name is empty.');
            return;
        }
        _fireEvent('presencenotification', presence.name, presence.state, _presenceTypes[presence.state], presence.activity);
    }


    /**
     * @method _supportsLocalStorage
     * @private
     * Checks if local storage is available
     */
    function _supportsLocalStorage() {
        try {
            return 'localStorage' in window && window.localStorage !== null;
        } catch (e) {
            return false;
        }
    }

    /**
     * @method _setUserInformationLocalStorage
     * @private
     * @param password Password to set
     * Set access token in local storage
     */
    function _setUserInformationLocalStorage(password) {
        localStorage['kandyphone.userinformation'] = _domainApiKey + ';' + _userDetails.full_user_id + ';' + password;
        return true;
    }

    /**
     * @method _getUserInformationLocalStorage
     * @private
     * Get access token from local storage
     */
    function _getUserInformationLocalStorage() {
        return localStorage['kandyphone.userinformation'];
    }

    /**
     * @method _clearAccessTokeLocalStorage
     * @private
     * Clears access token from local storage
     */
    function _clearAccessTokeLocalStorage() {
        localStorage.removeItem('kandyphone.userinformation');
        return true;
    }

    // TODO: Move configuration for different versions into a strategy pattern.

    /**
     * @method _mapSpidrConfigToAPI
     * @private
     * Maps the spider configs retrived from getSpiderConfiguration to fcs configs which can then be passed to fcs.setup
     */
    function _mapSpidrConfigToAPI(spidrConfig) {

        // In newer version (2.2.1+) we don't do any parsing of the parameters and pass them through directly if the server
        // configuration also supports it.
        if (spidrConfig.fcsApi) {
            return spidrConfig.fcsApi;
        }

        return {
            notificationType: fcs.notification.NotificationTypes.WEBSOCKET,
            restUrl: spidrConfig.REST_server_address,
            restPort: spidrConfig.REST_server_port,
            websocketIP: spidrConfig.webSocket_server_address,
            websocketPort: spidrConfig.webSocket_server_port,
            websocketProtocol: (spidrConfig.webSocket_secure !== false ? 'wss' : 'ws'),
            protocol: spidrConfig.REST_protocol,
            serverProvidedTurnCredentials: spidrConfig.serverProvidedTurnCredentials
        };
    }

    /**
     * @method _mapSpidrConfigToMedia
     * @private
     * Maps the spider configs retrived from getSpiderConfiguration to spidrEnv config which can then be passed to fcs.call.initMedia
     */
    function _mapSpidrConfigToMedia(spidrConfig) {

        // In newer version (2.2.1+) we don't do any parsing of the parameters and pass them through directly if the server
        // configuration also supports it.
        if (spidrConfig.fcsMedia) {
            return spidrConfig.fcsMedia;
        }

        if (spidrConfig.ICE_servers) {
            utils.extend(spidrConfig,
                {
                    'ICE_server_address': spidrConfig.ICE_servers[0],
                    'ICE_server_port': ''
                }
            );
        }

        return {
            iceserver: spidrConfig.ICE_server_address,
            iceserverPort: spidrConfig.ICE_server_port,
            webrtcdtls: spidrConfig.use_DTLS
        };
    }


    /**
     * @method _mergeConfigWithSpidrConfiguration
     * @private
     * merges _config with spidr config retrived from getSpidrConfiguration
     */

    function _mergeConfigWithSpidrConfiguration(spidrConfig) {

        // merge with configs from KandyAPI.Phone.setup
        _config.spidrApi = utils.defaults(_mapSpidrConfigToAPI(spidrConfig), _config.spidrApi);

        // apply default SPiDR configuration
        _config.spidrMedia = utils.defaults(_mapSpidrConfigToMedia(spidrConfig), _config.spidrMedia);

        if (_config.remoteVideoContainer) {
            _config.spidrMedia.remoteVideoContainer = _config.remoteVideoContainer;
        }

        if (_config.localVideoContainer) {
            _config.spidrMedia.localVideoContainer = _config.localVideoContainer;
        }

        if (_config.screenSharing) {
            _config.spidrMedia.screenSharing = _config.screenSharing;
        }

        if (_config.screenSharingChromeExtensionId) {
            _config.spidrMedia.screenSharingChromeExtensionId = _config.screenSharingChromeExtensionId;
        }
    }

    function _applySpiderConfiguration(spidrConfig, success, failure) {
        // merge _config with spirdConfig
        _mergeConfigWithSpidrConfiguration(spidrConfig);

        // setup SPiDR with fcsConfig
        fcs.setup(_config.spidrApi);

        fcs.setUserAuth(_userDetails.full_user_id, _userDetails.userPassword);
        //fcs.setUserAccessToken(_userDetails.userAccessToken);

        fcs.notification.start(
                function () {
                    _callStates = fcs.call.States;
                    // if the browser supports local storage persist the Access Token
                    if (_config.allowAutoLogin && _supportsLocalStorage()) {
                        _setUserInformationLocalStorage(_userDetails.userPassword);
                    }
                    success();
                },
                function (errorCode) {
                    _logger.error('login failed: unable to start spidr notification');
                    failure(errorCode);
                },
                false
        );
    }
    /**
     * @method _setup
     * @private
     * Logs in to Experius and SPiDR through fcs JSL
     * @param {String} userAccessToken Access token for user.
     * @param {String} password Password for user.
     */
    _logInToSpidr = function(success, failure) {
        _getSpidrConfiguration(
            function(spidrConfig) {
                _applySpiderConfiguration(spidrConfig, success, failure);
            },
            function (error) {
                _logger.error('login failed: unable to get spidr configuration');
                failure();
            }
        );
    };

    function _notificationHandler(message) {
        message = message.message;
        message = message && (message.kandyType || message.message_type);
        if (!message || message === 'gofetch') {
            _fireEvent('messagesavailable');
        } else if (message === 'incomingCall') {
            me._onIncommingCall('CALLavailable', message.call_id);
        }
    }

    registerWebSocketListeners({
        'notification': _notificationHandler
    });


    /**
     * @method setup
     * Setup Spdir
     * @param {Object} config Configuration.
     * @param {Array} [config.listeners={}] callback methods for KandyAPI events (see Events).
     * @param {String} [config.mediatorUrl="http://54.187.112.97:8080/kandywrapper-1.0-SNAPSHOT"] Rest endpoint for KandyWrapper.
     * @param {String} [config.allowAutoLogin=true] True to persist login information in local storage and auto login during setup
     * @param {Object} [config.fcsConfig] FCS Configuration
     * @param {KandyAPI.NOTIFICATION_TYPES} [config.fcsConfig.notificationType=KandyAPI.NOTIFICATION_TYPES.WEBSOCKET] Type of connection to use for notifications.
     * @param {String} [config.fcsConfig.restUrl="kandysimplexlb-231480754.us-east-1.elb.amazonaws.com"] Rest endpoint for spidr.
     * @param {String} [config.fcsConfig.cors=true] True to enable CORS support.
     * @param {String} [config.fcsConfig.restPort="443"] Port to use for rest endpoint.
     * @param {String} [config.fcsConfig.websocketIP="kandysimplexlb-231480754.us-east-1.elb.amazonaws.com"] Websocket endpoint for spidr.
     * @param {String} [config.fcsConfig.websocketPort="8581"] Port to use for websocket endpoint.
     * @param {String} [config.fcsConfig.disableNotifications=null] True to disable notifications.
     * @param {String} [config.fcsConfig.protocol="https"] Protocol to use http | https.
     * @param {Object} [config.spidrEnv] SPiDR Configuration.
     * @param {Object} [config.spidrEnv.iceserver="stun:206.165.51.23:3478"]
     * @param {Object} [config.spidrEnv.webrtcdtls=null]
     * @param {Object} [config.spidrEnv.remoteVideoContainer=""]
     * @param {Object} [config.spidrEnv.localVideoContainer=""]
     * @param {Object} [config.spidrEnv.pluginMode="auto"]
     * @param {Object} [config.spidrEnv.pluginLogLevel=2]
     * @param {Object} [config.spidrEnv.ice="STUN " + "stun:206.165.51.23:3478"]
     */
    me.setup = function(config) {
        _logger.warn('Deprecated method KandyAPI.Phone.setup use kandy.setup');
        api.setup(config);
    };

    _setupCall = function (config) {

        // apply default configuration
        _config = utils.extend(_config, config);

        fcs.notification.setOnConnectionEstablished(function () {
            _logger.info('Connection established');
            _fireEvent('onconnectionestablished', 'spider');
        });

        fcs.notification.setOnConnectionLost(function () {
            _logger.info('Connection Lost');
            _fireEvent('onconnectionlost', 'spider');
        });

        if (_config.allowAutoLogin && _supportsLocalStorage() && _getUserInformationLocalStorage()) {
            api.login(_getUserInformationLocalStorage().split(';')[0],
                    _getUserInformationLocalStorage().split(';')[1],
                    _getUserInformationLocalStorage().split(';')[2],
                    function () {
                        _fireEvent('loginsuccess', _userDetails);
                    },
                    function (msg, errorCode) {
                        _fireEvent('loginfailed', msg, errorCode);
                    }
            );
        }

        fcs.presence.onReceived = function (presence) {
            _handlePresenceNotification(presence);
        };

        fcs.call.onReceived = function (call) {
            _logger.info('incoming call');

            call.onStateChange = function (state) {
                _handleIncomingCallStateChange(call, state);
            };

            _handleCallNotification(call);
        };
    };

    /**
     * @method login
     * Login as a user
     * @Depracated
     * @param {String} domainApiKey
     * @param {String} userName
     * @param {String} userPassword
     */
    me.login = function (domainApiKey, userName, password) {
        _logger.warn('Deprecated method KandyAPI.Phone.login use kandy.login');

        api.login(domainApiKey, userName, password,
                function () {
                    _fireEvent('loginsuccess', _userDetails);
                },
                function (errorCode) {
                    _fireEvent('loginfailed', '', errorCode);
                }
        );
    };


    me.initMedia = function (success, failure, force) {
        if ((force === undefined || !force) && _initMediaDone) {
            success();
            return;
        }

        // make sure the browser supports WebRTC
        fcs.call.initMedia(
                function () {
                    _logger.info('media initiated');
                    _mediaInitiated = true;

                    // add unload event to end any calls
                    window.addEventListener('beforeunload', function (event) {
                        for (var i in _calls) {
                            me.endCall(i);
                        }
                    });
                    _initMediaDone = true;
                    success();
                },
                function (errorCode) {
                    _logger.error('Problem occurred while initiating media');

                    switch (errorCode) {
                        case fcs.call.MediaErrors.WRONG_VERSION:
                            _logger.error('Media Plugin Version Not Supported');
                            _fireEvent('media', {type: me.MediaErrors.WRONG_VERSION});
                            break;
                        case fcs.call.MediaErrors.NEW_VERSION_WARNING:
                            _logger.error('New Plugin Version is available');
                            _fireEvent('media',
                                    {// event
                                        type: me.MediaErrors.NEW_VERSION_WARNING,
                                        urlWin32bit: 'https://kandy-portal.s3.amazonaws.com/public/plugin/3.0.476/Kandy_Plugin_3.0.476.exe',
                                        urlWin64bit: 'https://kandy-portal.s3.amazonaws.com/public/plugin/3.0.476/Kandy_Plugin_3.0.476_x86_64.exe',
                                        urlMacUnix: 'https://kandy-portal.s3.amazonaws.com/public/plugin/3.0.476/Kandy_Plugin_3.0.476.pkg'
                                    }
                            );
                            break;
                        case fcs.call.MediaErrors.NOT_INITIALIZED:
                            _logger.error('Media couldn\'t be initialized');
                            _fireEvent('media', {type: me.MediaErrors.NOT_INITIALIZED});
                            break;
                        case fcs.call.MediaErrors.NOT_FOUND:
                            _logger.error('Plugin couldn\'t be found!');
                            _fireEvent('media',
                                    {// event
                                        type: me.MediaErrors.NOT_FOUND,
                                        urlWin32bit: 'https://kandy-portal.s3.amazonaws.com/public/plugin/3.0.476/Kandy_Plugin_3.0.476.exe',
                                        urlWin64bit: 'https://kandy-portal.s3.amazonaws.com/public/plugin/3.0.476/Kandy_Plugin_3.0.476_x86_64.exe',
                                        urlMacUnix: 'https://kandy-portal.s3.amazonaws.com/public/plugin/3.0.476/Kandy_Plugin_3.0.476.pkg'
                                    }
                            );
                            break;
                        case fcs.call.MediaErrors.NO_SCREEN:
                            _logger.info('ScreenShare extension could not be found');
                            _fireEvent('media',
                                    {// event
                                        type: me.MediaErrors.NO_SCREEN
                                    }
                            );
                            //We should not stop for this reason
                            _initMediaDone = true;
                            break;
                    }

                    failure(errorCode);
                },
                utils.defaults({
                    remoteVideoContainer: _config.spidrMedia.remoteVideoContainer,
                    localVideoContainer: _config.spidrMedia.localVideoContainer
                }, _config.spidrMedia)
        );
    };

    _logOutOfSpidr = function(success){
        // if the browser supports local storage clear out the stored access token
        if (_supportsLocalStorage()) {
            _clearAccessTokeLocalStorage();
        }

        fcs.clearResources(function () {
            if (success) {
                success();
            }
        }, true);
    };


    /**
     * @method logout
     * Logs out
     * @param {Function} success The success callback.
     */
    me.logout = function (success) {
        _logger.info('KandyAPI.Phone.logout is deprecated use kandy.logout');

        api.logout(success);
    };

    /**
     * @method hasStoredLogin
     * Returns true if login information has been stored in local storage
     */
    me.hasStoredLogin = function () {
        if (_supportsLocalStorage()) {
            _getUserInformationLocalStorage();
        }
    };

    /**
     * @method isMediaInitialized
     * Returns true if media is initialized
     */
    me.isMediaInitiated = function () {
        return _mediaInitiated;
    };

    /**
     * @method isIncoming
     * @param {String} callId The id of the call.
     * returns true if call is incoming
     */
    me.isIncoming = function (callId) {
        var call = _calls[callId];

        return call.isIncoming;
    };

    /**
     * @method isOutgoing
     * @param {String} callId The id of the call.
     * Returns true if call is outgoing
     */
    me.isOutgoing = function (callId) {
        var call = _calls[callId];

        return call.isOutgoing;
    };

    /**
     * @method callTypes
     * Gets call types
     * See call types enumeration
     */
    me.callTypes = function () {
        return _callTypes;
    };

    /**
     * @method getAnonymousData
     * @param {String} callId The id of the call to get the Anonymous data for.
     * returns anonymous data if the call is anonymous null if not.
     */
    me.getAnonymousData = function (callId) {
        var call = _call[callId];

        if (call && call.isAnonymous) {
            return call.callerName;
        } else {
            return null;
        }
    };

    /**
     * @method callType
     * @param {String} callId The id of the call.
     * returns call type either incomming or outgoing
     */
    me.callType = function (callId) {
        var call = _calls[callId];

        if (call.isIncoming) {
            return _callTypes.INCOMING_CALL;
        }
        else if (call.isOutgoing) {
            return _callTypes.OUTGOING_CALL;
        }
    };

    /**
     * @method makeSIPCall
     * Starts SIP call using the configured sipOutnumber
     * @param {String} number The number to call.
     */
    me.makeSIPCall = function (number, callerId) {
        me.makeCall(_config.sipOutNumber + number + '@' + _userDetails.domain_name, false, callerId);
    };

    /**
     * @method makePSTNCall
     * Starts PSTN call using the configured pstnOutNumber
     * @param {String} number The number to call.
     */
    me.makePSTNCall = function (number, callerId) {
        me.makeCall(_config.pstnOutNumber + number + '@' + _userDetails.domain_name, false, callerId);
    };

    /**
     * @method makeCall
     * Starts call
     * @param {String} number The number to call.
     * @param {Boolean} cameraOn Whether to turn one's own camera on
     * @param {String} callerId What you want the caller ID to look like to callee
     */
    me.makeCall = function (number, cameraOn, callerId) {
        _logger.info('making voice call');

        me.initMedia(
            function () {
                if (number === _userDetails.full_user_id) {
                  _fireEvent('callinitiatefailed', 'You cannot call yourself');
                    return;
                }

                fcs.call.startCall(fcs.getUser(), {firstName: callerId}, number,
                    //onSuccess
                    function (outgoingCall) {
                        outgoingCall.onStateChange = function (state, statusCode) {
                            outgoingCall.statusCode = statusCode;

                            _handleOutgoingCallStateChange(outgoingCall, state);
                        };

                        outgoingCall.isAnonymous = false;
                        _calls[outgoingCall.getId()] = outgoingCall;

                        _fireEvent('callinitiated', outgoingCall, number);
                    },
                    //onFailure
                    function (errorCode) {
                        _logger.error('call failed');
                        _fireEvent('callinitiatefailed', 'Start call failed: ' + errorCode);

                    }, true, cameraOn);
            },
            function (errorCode) {
                _logger.error('call failed');
                _fireEvent('callinitiatefailed', 'Init media failed: ' + errorCode);
            }
        );
    };

    function makeAnonymousCall(domainApiKey, account, caller, callee, cli, cameraOn){
      _initLogger();

      _kandyRequest({
          url: '/domains/configurations/communications/spidr',
          params: { key: domainApiKey },
          success: applyConfiguration,
          failure: function() {
              _fireEvent('callinitiatefailed', 'Failed to retrieve domain configuration');
              _logger.error('Call Failed: Failed to retrieve domain configuration');
          }
      });

      function applyConfiguration(config) {

          _mergeConfigWithSpidrConfiguration(config.result.spidr_configuration);

          fcs.setup(_config.spidrApi);

          //Setup user credential
          fcs.setUserAuth(account, '');

          fcs.notification.start(
              function () {
                  _logger.info('Notification started');

                  _callStates = fcs.call.States;

                  me.initMedia(
                      function () {
                          _logger.info('Call init successfully');
                          //TODO: do we need setTimeout
                          setTimeout(function () {

                              fcs.call.startCall(caller, cli, callee,
                                  //onSuccess
                                  function (outgoingCall) {
                                      outgoingCall.onStateChange = function (state, statusCode) {
                                          outgoingCall.statusCode = statusCode;

                                          _handleOutgoingCallStateChange(outgoingCall, state);
                                      };

                                      outgoingCall.isAnonymous = true;
                                      _calls[outgoingCall.getId()] = outgoingCall;
                                      _fireEvent('callinitiated', outgoingCall, callee);
                                  },
                                  //onFailure
                                  function (errorCode) {
                                      _logger.error('call failed');
                                      _fireEvent('callinitiatefailed', 'error code: ' + errorCode);

                                  }, false, cameraOn);

                          }, 100);
                      },
                      function (errorCode) {
                          _logger.error('Call init failed');
                          api.logout();
                          _fireEvent('callinitiatefailed', 'Init media failed: ' + errorCode);
                      }
                  );
              },
              function () {
                  console.error('Notification failed');
                  _fireEvent('callinitiatefailed', 'Auth failed');
              }, true);
      }
    }

    /**
     * @method makeAnonymousCallWithToken
     * Starts Anonymous video call using tokens
     * @param {String} domainApiKey The Domain API Key for the domain on which the call will be made.
     * @param {String} tokenRealm The realm used to encrypt the tokens
     * @param {String} acountToken The encoded account token used to make the call
     * @param {String} fromToken The encoded origination for the call
     * @param {String} toToken The encoded destination for the call
     * @param {Boolean} cameraOn Whether call is made with camera on
     */
    me.makeAnonymousCallWithToken = function (domainApiKey, tokenRealm, acountToken, fromToken, toToken, cameraOn){
      fcs.setRealm(tokenRealm);
      makeAnonymousCall(domainApiKey, acountToken, fromToken, toToken, null, cameraOn);
    };

    /**
     * @method makeAnonymousCall
     * Starts Anonymous video call
     * @param {String} domainApiKey The Domain API Key for the domain on which the call will be made.
     * @param {String} calleeUsername The Kandy user being called (callee)
     * @param {String} anonymousData Data to send with anonymous call
     * @param {String} callerUserName The Kandy user making the call (caller)
     * @param {Boolean} cameraOn Whether call is made with camera on
     */
    me.makeAnonymousCall = function (domainApiKey, calleeUsername, anonymousData, callerUserName, cameraOn) {
      var anonymousUserName = {
          firstName: anonymousData
      };
      callerUserName = callerUserName || 'anonymous@concierge.com';
      makeAnonymousCall(domainApiKey, callerUserName, callerUserName, calleeUsername, anonymousUserName, cameraOn);
    };


    /**
     * @method rejectCall
     * reject incoming call
     * @param {String} callId Id of call.
     */
    me.rejectCall = function (callId) {
        var call = _calls[callId];
        call.reject(
                function () {
                    _fireEvent('callrejected', call);
                },
                function (errorCode) {
                    _logger.info('reject failed');
                    _fireEvent('callrejectfailed', call, errorCode);
                }
        );
    };

    /**
     * @method ignoreCall
     * ignore incoming call
     * @param {String} callId Id of call.
     */
    me.ignoreCall = function (callId) {
        var call = _calls[callId];
        call.ignore(
                function () {
                    _fireEvent('callignored', call);
                },
                function (errorCode) {
                    _fireEvent('callignorefailed', call, errorCode);
                    _logger.info('ignore failed');
                }
        );
    };

    /**
     * @method answerCall
     * Answer voice call
     * @param {String} callId Id of call.
     * @param {Boolean} cameraOn Whether to turn one's own camera on
     */
    me.answerCall = function (callId, cameraOn) {
        me.initMedia(function () {
            var call = _calls[callId];
            call.answer(function () {
                        _fireEvent('callanswered', call, call.isAnonymous);
                    },
                    function (errorCode) {
                        _logger.info('answer failed');
                        _fireEvent('callanswerfailed', call, errorCode);
                    },
                    cameraOn
            );
        },
            function (errorCode) {
                _logger.info('answer failed');
                _fireEvent('callanswerfailed');
            }
        );
    };

    /**
     * @method muteCall
     * Mutes current call
     * @param {String} callId Id of call.
     */
    me.muteCall = function (callId) {
        var call = _calls[callId];
        if (call) {
            call.mute();
            call.isMuted = true;
        }
    };

    /**
     * @method unMuteCall
     * Unmutes current call
     * @param {String} callId Id of call.
     */
    me.unMuteCall = function (callId) {
        var call = _calls[callId];
        if (call) {
            call.unmute();
            call.isMuted = false;
        }
    };

    /**
     * @method holdCall
     * Holds current call
     * @param {String} callId Id of call.
     * @param {Function} success The success callback.
     * @param {Function} failure The failure callback.
     */
    me.holdCall = function (callId, success, failure) {
        var call = _calls[callId];
        if (call) {
            call.hold(success, failure);
            call.held = true;
        }
    };

    /**
     * @method unHoldCall
     * Removes hold on current call
     * @param {String} callId Id of call.
     * @param {Function} success The success callback.
     * @param {Function} failure The failure callback.
     */
    me.unHoldCall = function (callId, success, failure) {
        var call = _calls[callId];
        if (call) {
            call.unhold(success, failure);
            call.held = false;
        }
    };

    /**
     * @method startCallVideo
     * Starts video on call
     * @param {String} callId Id of call.
     * @param {Function} success The success callback.
     * @param {Function} failure The failure callback.
     */
    me.startCallVideo = function (callId, success, failure) {
        var call = _calls[callId];
        if (call) {
            call.videoStart(success, failure);
        }
    };

    /**
     * @method stopCallVideo
     * Stops video on call
     * @param {String} callId Id of call.
     * @param {Function} success The success callback.
     * @param {Function} failure The failure callback.
     */
    me.stopCallVideo = function (callId, success, failure) {
        var call = _calls[callId];
        if (call) {
            call.videoStop(success, failure);
        }
            };
    me.startScreenSharing = function (callId, success, failure, stopped, resolution, frameRate) {
        var call = _calls[callId];
        if (call) {
            call.screenSharingStart(success, failure, stopped, resolution, frameRate);
        }
            };

    me.stopScreenSharing = function (callId, success, failure) {
       var call = _calls[callId];
       if (call) {
           call.screenSharingStop(success, failure);
        }
    };

    /**
     * @method sendDTMF
     * sends tones on a call
     * @param {String} callId Id of call.
     * @param {String} tones A string of tones
     */
    me.sendDTMF = function (callId, tones) {
        var call = _calls[callId];
        if (call) {
            call.sendDTMF(tones);
        }
    };

    /**
     * @method endCall
     * Ends call
     * @param {String} callId Id of call.
     */
    me.endCall = function (callId) {
        var call = _calls[callId];

        if (call) {
            _logger.info('ending call');
            call.end(
                    function () {
                        _stopIntraFrame(call);

                        delete _calls[callId];

                        if (call.isAnonymous && call.isOutgoing) {
                            fcs.clearResources(function () {
                            }, true);
                        }

                        _fireEvent('callended', call);
                    },
                    function (errorCode) {
                        _logger.error('COULD NOT END CALL');
                        _fireEvent('callendfailed', call, errorCode);
                    }
            );
        }
    };

    /**
     * @method watchPresence
     * Sets up watching for presence change of contacts.
     */
    me.watchPresence = function (list, success, failure) {

        _logger.warn('KandyAPI.Phone.watchPresence is deprecated please use kandy.getLastSeen');

        var contactList = [];

        fcs.presence.watch(
                list.map(function (item) {
                    return item.full_user_id;
                }),
                function () {
                    _logger.info('Watch presence successful');
                    if (success) {
                        success();
                    }
                },
                function () {
                    _logger.error('Watch presence error');
                    if (failure) {
                        failure();
                    }
                }
        );
    };

    /**
     * @method updatePresence
     * Sets presence for logged in user.
     */
    me.updatePresence = function (status) {
        _logger.warn('KandyAPI.Phone.updatePresence is deprecated please use kandy.getLastSeen');
        if (fcs.getServices().presence === true) {
            fcs.presence.update(parseInt(status),
                    function () {
                        _logger.info('Presence update success');
                    },
                    function () {
                        _logger.error('Presence update failed');
                    });
        } else {
            _logger.error('Presence service not available for account');
        }
    };

    me.normalizeNumber = function (number, countryCode, success, failure) {
        _kandyRequest({
            url: '/users/services/normalize/phone_number',
            params: {
                'phone_number': number,
                'countryCode': countryCode
            },
            success: function (response) {
                if (success) {
                    success(response.result);
                }
            },
            failure: failure
        });
    };

    function _getSpidrConfiguration(success, failure) {
        _kandyRequest({
            url: '/users/configurations/communications/spidr',
            params: {
                secure: true
            },
            success: function (response) {
                if (success) {
                    success(response.result.spidr_configuration);
                }
            },
            failure: failure
        });
    }

    /**
     * @method getSpidrConfiguration
     * Retrieves spidr configuration
     * @param {Function} userAccessToken User Access Token.
     * @param {Function} success The success callback.
     * @param {Function} failure The failure callback.
     */
    me.getSpidrConfiguration = _getSpidrConfiguration;

    return me;
}());

//=================================================================
//=========================== AddressBook ===============================
//=================================================================

api.addressbook = (function () {
    var me = {};

    /**
     * @method searchDirectoryByPhoneNumber
     * @param {String} phoneNumber The name to search for.
     * @param {Function} success The success callback.
     * @param {Function} failure The failure callback.
     * Search directory for user.
     */
    me.searchDirectoryByPhoneNumber = function (phoneNumber, success, failure) {
        _kandyRequest({
            url: '/users/directories/native/searches/phone_number',
            params: {
                'search_string': phoneNumber
            },
            success: function (response) {
                if (success) {
                    success(response.result.contacts);
                }
            },
            failure: failure
        });
    };

    /**
     * @method searchDirectoryByName
     * @param {String} name The name to search for
     * @param {Function} success The success callback.
     * @param {Function} failure The failure callback.
     * Search directory for user.
     */
    me.searchDirectoryByName = function (name, success, failure) {
        _kandyRequest({
            url: '/users/directories/native/searches/name',
            params: {
                'search_string': name
            },
            success: function (response) {
                if (success) {
                    success(response.result.contacts);
                }
            },
            failure: failure
        });
    };

    /**
     * @method searchDirectoryByUserName
     * @param {String} username Username to search for.
     * @param {Function} success The success callback.
     * @param {Function} failure The failure callback.
     * Search directory for user.
     */
    me.searchDirectoryByUserName = function (username, success, failure) {
        _kandyRequest({
            url: '/users/directories/native/searches/user_id',
            params: {
                'search_string': username
            },
            success: function (response) {
                if (success) {
                    success(response.result.contacts);
                }
            },
            failure: failure
        });
    };

    /**
     * @method searchDirectory
     * @param {String} searchString can first name, last name, user ID or phone number.
     * @param {Function} success The success callback.
     * @param {Function} failure The failure callback.
     * Generic search directory for user.
     */
    me.searchDirectory = function (searchString, success, failure) {
        _kandyRequest({
            url: '/users/directories/native/search/',
            params: {
                'search_string': searchString
            },
            success: function (response) {
                if (success) {
                    success(response.result.contacts);
                }
            },
            failure: failure
        });
    };

    /**
     * @method retrieveDirectory
     * @param {Function} success The success callback.
     * @param {Function} failure The failure callback.
     * Retrieves directory entries.
     */
     me.retrieveDirectory = function (success, failure) {
        _kandyRequest({
            url: '/users/directories/native',
            success: function (response) {
                if (success && response.result && response.result.contacts) {
                    response.result.contacts.forEach(function (contact) {
                        contact.firstName = contact.user_first_name;
                        contact.lastName = contact.user_last_name;
                        contact.number = contact.user_phone_number;
                        contact.hintType = 'community';
                        delete contact.user_first_name;
                        delete contact.user_last_name;
                    });
                    success(response.result);
                }
            },
            failure: failure
        });
    };
    /**
     * @method retrievePersonalAddressBook
     * @param {String} userAccessToken
     * @param {Function} success The success callback.
     * @param {Function} failure The failure callback.
     * Retrieves address book entries.
     */
    me.retrievePersonalAddressBook = function (success, failure) {
        _kandyRequest({
            url: '/users/addressbooks/personal',
            success: function (response) {
                if (success) {
                    success(response.result.contacts);
                }
            },
            failure: failure
        });
    };

    /**
     * @method addToPersonalAddressBook
     * @param {String} userAccessToken
     * @param {Object} entry Object container properties of the entry to add.
     * @param {Object} entry.username Object container properties of the entry to add.
     * @param {Object} entry.nickname  Nickname for address book entry.
     * @param {Object} [entry.firstName] first name for address book entry.
     * @param {Object} [entry.lastName] last name for address book entry.
     * @param {Object} [entry.homePhone] home phone for address book entry.
     * @param {Object} [entry.mobileNumber] mobile number for address book entry.
     * @param {Object} [entry.businessPhone] business phone for address book entry.
     * @param {Object} [entry.fax] fax for address book entry.
     * @param {Object} [entry.email] email for address book entry.
     * @param {Function} success The success callback.
     * @param {Function} failure The failure callback.
     * Adds kandy user to current kandy user's address book.
     */
    me.addToPersonalAddressBook = function (entry, success, failure) {
        _kandyRequest({
            type: 'POST',
            url: '/users/addressbooks/personal',
            data: {contact: entry},
            success: function (response) {
                if (success) {
                    success(response.result);
                }
            },
            failure: failure
        });
    };

    /**
     * @method removeFromPersonalAddressBook
     * @param {String} contactId Contact ID for the contact.
     * @param {Function} success The success callback.
     * @param {Function} failure The failure callback.
     * Retrieves address book entries.
     */
    me.removeFromPersonalAddressBook = function (contactId, success, failure) {
        _kandyRequest({
            type: 'DELETE',
            url: '/users/addressbooks/personal',
            params: {
                'contact_id': contactId
            },
            success: function (response) {
                if (success) {
                    success();
                }
            },
            failure: failure
        });
    };

    /**
     /**
     * @method retrieveDeviceAddressBook
     * Retrieve the network address book
     * @param {String} userAccessToken
     * @param {Function} success The success callback.
     * @param {Function} failure The failure callback.
     * @return {Object} response object with success being true or false
     */
    me.retrieveUserDeviceAddressBook = function (success, failure) {
        _kandyRequest({
            url: '/users/addressbooks/device',
            success: function (response) {
                if (success) {
                    success(response.result);
                }
            },
            failure: failure
        });
    };

    return me;
}());



//=================================================================
//======================= REGISTRATION ============================
//=================================================================
/**
 * @author Russell Holmes
 * KandyAPI.Registration
 * @singleton
 * Registration is used to register with the Kandy API.
 *
 * Simply create a new KandyAPI phone instance passing in your configuration
 *
 *     KandyAPI.Registration.setup({
 *       listeners:{
 *           callinitiated: function(call, number){
 *              // Call has been initiated.
 *           }
 *       }
 *     });
 */
api.Registration = api.registration = (function () {
    var me = {};

    /**
     * @property {String} _config Domain Access Code.
     * @private
     */
    var _domainAccessToken = null;

    /**
     * @method _fireEvent
     * Fires passed event
     * @private
     */
    function _fireEvent() {
        var eventName = Array.prototype.shift.apply(arguments);

        if (me.events[eventName]) {
            me.events[eventName].apply(me, arguments);
        }
    }

    /**
     * @method setup
     * @param {Object} config Configuration.
     * @param {Array} [config.listeners={}] Listeners for KandyAPI.Registration.
     * @param {String} [config.mediatorUrl="http://api.kandy.io"] Rest endpoint for KandyWrapper.
     */
    me.setup = function (config) {

        // setup default configuration
        _config = utils.extend(_config, config);

        me._domainAccessToken = config.domainAccessToken;

        // setup listeners
        //TODO me.events realy needed for KandyAPI.Registration?
        /*
        if (_config.listeners) {
            for (var listener in _config.listeners) {

                // TODO: This has to be a bug right? We're only adding the listener if it's already defined?
                if (me.events[listener] !== undefined) {
                    me.events[listener] = _config.listeners[listener];
                }
            }
        }

        */
        _logger = fcs.logManager.getLogger();
    };

    /**
     * @method retrieveCountryCode
     * Retrieves county code based on Device
     * @param {Function} success The success callback.
     * @param {Function} failure The failure callback.
     */
    me.retrieveCountryCode = function (success, failure) {
        _kandyRequest({
            url: '/domains/countrycodes',
            params: {
                key: me._domainAccessToken
            },
            success: function (response) {
                if (success) {
                    success(response.result);
                }
            },
            failure: failure
        });
    };

    /**
     * @method sendValidationCode
     * Send validation code to phone
     * @param {String} phoneNumber Phone number to send validation SMS to.
     * @param {Function} success The success callback.
     * @param {Function} failure The failure callback.
     */
    me.sendValidationCode = function (phoneNumber, countryCode, success, failure) {
        _kandyRequest({
            type: 'POST',
            url: '/domains/verifications/smss',
            params: {
                key: me._domainAccessToken
            },
            data: {
                'user_phone_number': phoneNumber,
                'user_country_code': countryCode
            },
            success: success,
            failure: failure
        });
    };

    /**
     * @method validateCode
     * Validate SMS code sent to phone
     * @param {String} validationCode Validation code sent to phone.
     * @param {Function} success The success callback.
     * @param {Function} failure The failure callback.
     */
    me.validateCode = function (validationCode, success, failure) {
        var encodedAccessCode = encodeURIComponent(me._domainAccessToken);

        _kandyRequest({
            url: '/domains/verifications/codes',
            params: {
                key: me._domainAccessToken,
                'validation_code': validationCode
            },
            success: function (response) {
                if (success) {
                    success(response.result.valid);
                }
            },
            failure: failure
        });
    };

    me.getUserInfo = function (success, failure) {
        _kandyRequest({
            url: '/users/billing/packages/status/active',
            success: function (response) {
                if (success) {
                    success(response.result);
                }
            },
            failure: failure
        });
    };

    me.getProfileInfo = function (userId, domainId, success, failure) {

        _kandyRequest({
            url: '/users/profiles/user_profiles/user_profile',
            params: {
                'user_id': userId,
                'domain_name': domainId
            },
            success: function (response) {
                if (success) {
                    success(response.result);
                }
            },
            failure: failure
        });
    };

    // TODO: Document, and set parameters to camel case.
    me.setProfileInfo = function (data, success, failure) {
        _kandyRequest({
            type: 'POST',
            url: '/users/profiles/user_profiles',
            params: {
                'first_name': data.first_name,
                'last_name': data.last_name,
                'status_text': data.status_text,
                'image_details': data.image_details,
                'user_data': data.user_data
            },
            success: function (response) {
                if (success) {
                    success();
                }
            },
            failure: failure
        });
    };


    /**
     * @method register a device
     * Registers a device in Kandy
     * @param {Object}
     * e.g. {
     *        {String} domainAccessToken: "7b81d8e63f5b478382b4e23127260090", // optional
     *        {String} userPhoneNumber: "4034932232",
     *        {String} userCountryCode "UA",
     *        {String} validationCode "1234",
     *        {String} deviceNativeId "3456",
     *        {String} deviceFamily "iPhone",  // optional
     *        {String} deviceName "myPhone",  // optional
     *        {String} clientSwVersion "4",  // optional
     *        {String} deviceOsVersion "801",  // optional
     *        {String} userPassword "pwdxyz13!",  // optional
     *        {Function} success = function() { doSomething(); }
     *        {Function} failure = function() { doSomethingElse(); }
     *   }
     * @return {Object} response object
     * e.g. { user_id: "972542405850",
     full_user_id: "972542405850@domain.com",
     domain_name:  "domain.com",
     user_access_token: "4d405f6dfd9842a981a90daaf0da08fa",
     device_id: "4d405f6dfd9842a389d5b45d65a9dfd0"
     }
     */
    me.register = function (params, success, failure) {
        _kandyRequest({
            type: 'POST',
            url: '/api_wrappers/registrations',
            params: {
                // TODO "internal server error" if client_sw_version and client_sw_type are used.
                // 'client_sw_version': api.version,
                // 'client_sw_type': 'JS',

                key: me._domainAccessToken
            },
            data: {

                'user_phone_number': params.userPhoneNumber,
                'user_country_code': params.userCountryCode,
                'validation_code': params.validationCode,
                'device_native_id': params.deviceNativeId
            },
            success: function (response) {
                if (success) {
                    success(response.result);
                }

            },
            failure: failure
        });
    };

    /**
     * @method getConfiguration
     * Retrieves domain name, access token, and SPiDR configuration
     * @param {String} domainApiKey
     * @param {String} domainApiSecret
     * @param {Function} success The success callback.
     * @param {Function} failure The failure callback.
     * @return {Object} response object
     * e.g. {
     "domain_name": "domain.com",
     "domain_access_token": "4d405f6dfd9842a981a90daaf0da08fa",
     "spidr_configuration":
     {
     "REST_server_address":"kandysimplex.fring.com",
     "REST_server_port":443,
     "webSocket_server_address":"kandysimplex.fring.com",
     "webSocket_server_port":8582,
     "ICE_server_address":"54.84.226.174",
     "ICE_server_port":3478,
     "subscription_expire_time_seconds":null,
     "REST_protocol":"https",
     "server_certificate":null,
     "use_DTLS":false,
     "audit_enable":true,
     "audit_packet_frequency":null
     }
     }
     */

    me.getConfiguration = function (params, success, failure) {
        _kandyRequest({
            url: '/api_wrappers/configurations',
            params: {
                key: params.domainApiKey,
                'domain_api_secret': params.domainApiSecret
            },
            success: function (response) {
                if (success) {
                    success({
                        domainName: response.result.domain_name,
                        domainAccessToken: response.result.domain_access_token,
                        spidrConfiguration: {
                            restUrl: response.result.spidr_configuration.REST_server_address,
                            restPort: response.result.spidr_configuration.REST_server_port,
                            protocol: response.result.spidr_configuration.REST_protocol,
                            websocketIP: response.result.spidr_configuration.webSocket_server_address,
                            websocketPort: response.result.spidr_configuration.webSocket_server_port,
                            'spidr_env': {
                                iceserver: ('stun:' + response.result.spidr_configuration.ICE_server_address + ':' +
                                        response.result.spidr_configuration.ICE_server_port),
                                ice: ('STUN stun:' + response.result.spidr_configuration.ICE_server_address + ':' +
                                        response.result.spidr_configuration.ICE_server_port)

                            }
                        }
                    });
                }
            },
            failure: failure
        });
    };

    return me;
}());


    //Announced deprecation in 2.2.0

    api.Phone.sendSMS = function (){
        _logger.warn('KandyAPI.Phone.sendSMS is deprecated please use kandy.messaging.sendSMS');
        return api.messaging.sendSMS.apply(null, arguments);
    };

    api.Phone.sendIm = function (){
        _logger.warn('KandyAPI.Phone.sendIm is deprecated please use kandy.messaging.sendIm');
        return api.messaging.sendIm.apply(null, arguments);
    };
    api.Phone.sendJSON = function (){
        _logger.warn('KandyAPI.Phone.sendJSON is deprecated please use kandy.messaging.sendJSON');
        return api.messaging.sendJSON.apply(null, arguments);
    };
    api.Phone.sendImWithFile = function (){
        _logger.warn('KandyAPI.Phone.sendImWithFile is deprecated please use kandy.messaging.sendImWithFile');
        return api.messaging.sendImWithFile.apply(null, arguments);
    };
    api.Phone.sendImWithImage = function (){
        _logger.warn('KandyAPI.Phone.sendImWithImage is deprecated please use kandy.messaging.sendImWithImage');
        return api.messaging.sendImWithImage.apply(null, arguments);
    };
    api.Phone.sendImWithAudio = function (){
        _logger.warn('KandyAPI.Phone.sendImWithAudio is deprecated please use kandy.messaging.sendImWithAudio');
        return api.messaging.sendImWithAudio.apply(null, arguments);
    };
    api.Phone.sendImWithVideo = function (){
        _logger.warn('KandyAPI.Phone.sendImWithVideo is deprecated please use kandy.messaging.sendImWithVideo');
        return api.messaging.sendImWithVideo.apply(null, arguments);
    };
    api.Phone.uploadFile = function (){
        _logger.warn('KandyAPI.Phone.uploadFile is deprecated please use kandy.messaging.uploadFile');
        return api.messaging.uploadFile.apply(null, arguments);
    };
    api.Phone.buildFileUrl = function (){
        _logger.warn('KandyAPI.Phone.buildFileUrl is deprecated please use kandy.messaging.buildFileUrl');
        return api.messaging.buildFileUrl.apply(null, arguments);
    };
    api.Phone.buildFileThumbnailUrl = function (){
        _logger.warn('KandyAPI.Phone.buildFileThumbnailUrl is deprecated please use kandy.messaging.buildFileThumbnailUrl');
        return api.messaging.buildFileThumbnailUrl.apply(null, arguments);
    };

    api.Phone.getIm = function (){
        _logger.warn('KandyAPI.Phone.getIm is deprecated please use kandy.messaging.getIm');
        return api.messaging.getIm.apply(null, arguments);
    };

    api.Phone.clearIm = function (){
        _logger.warn('KandyAPI.Phone.clearIm is deprecated please use kandy.messaging.clearIm');
        return api.messaging.clearIm.apply(null, arguments);
    };

    api.Phone.searchDirectoryByPhoneNumber = function (){
        _logger.warn('KandyAPI.Phone.searchDirectoryByPhoneNumber is deprecated please use kandy.addressbook.searchDirectoryByPhoneNumber');
        return api.addressbook.searchDirectoryByPhoneNumber.apply(null, arguments);
    };
    api.Phone.searchDirectoryByName = function (){
        _logger.warn('KandyAPI.Phone.searchDirectoryByName is deprecated please use kandy.addressbook.searchDirectoryByName');
        return api.addressbook.searchDirectoryByName.apply(null, arguments);
    };
    api.Phone.searchDirectoryByUserName = function (){
        _logger.warn('KandyAPI.Phone.searchDirectoryByUserName is deprecated please use kandy.addressbook.searchDirectoryByUserName');
        return api.addressbook.searchDirectoryByUserName.apply(null, arguments);
    };
    api.Phone.searchDirectory = function (){
        _logger.warn('KandyAPI.Phone.searchDirectory is deprecated please use kandy.addressbook.searchDirectory');
        return api.addressbook.searchDirectory.apply(null, arguments);
    };
    api.Phone.retrievePersonalAddressBook = function (){
        _logger.warn('KandyAPI.Phone.retrievePersonalAddressBook is deprecated please use kandy.addressbook.retrievePersonalAddressBook');
        api.addressbook.retrievePersonalAddressBook.apply(null, arguments);
    };
    api.Phone.addToPersonalAddressBook = function (){
        _logger.warn('KandyAPI.Phone.addToPersonalAddressBook is deprecated please use kandy.addressbook.addToPersonalAddressBook');
        return api.addressbook.addToPersonalAddressBook.apply(null, arguments);
    };
    api.Phone.removeFromPersonalAddressBook = function (){
        _logger.warn('KandyAPI.Phone.removeFromPersonalAddressBook is deprecated please use kandy.addressbook.removeFromPersonalAddressBook');
        return api.addressbook.removeFromPersonalAddressBook.apply(null, arguments);
    };
    api.Phone.retrieveUserDeviceAddressBook = function (){
        _logger.warn('KandyAPI.Phone.retrieveUserDeviceAddressBook is deprecated please use kandy.addressbook.retrieveUserDeviceAddressBook');
        return api.addressbook.retrieveUserDeviceAddressBook.apply(null, arguments);
    };


    return api;
}));
