;;; gptel-xai-oauth.el --- gptel support for SuperGrok/xAI subscription plan  -*- lexical-binding: t; -*-

;; Copyright (C) 2026  Karthik Chikmagalur

;; Author: Karthik Chikmagalur <karthikchikmagalur@gmail.com>

;; This program is free software; you can redistribute it and/or modify
;; it under the terms of the GNU General Public License as published by
;; the Free Software Foundation, either version 3 of the License, or
;; (at your option) any later version.

;; This program is distributed in the hope that it will be useful,
;; but WITHOUT ANY WARRANTY; without even the implied warranty of
;; MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
;; GNU General Public License for more details.

;; You should have received a copy of the GNU General Public License
;; along with this program.  If not, see <https://www.gnu.org/licenses/>.

;;; Commentary:

;; Provides support for SuperGrok / xAI OAuth 2.0 authentication in gptel.

;;; Code:

(require 'cl-lib)
(require 'gptel-openai)
(require 'gptel-oauth)

(defconst gptel--xai-oauth-client-id "b1a00492-073a-47ea-816f-4c329264a828")
(defconst gptel--xai-oauth-url "https://auth.x.ai")

(defvar gptel--xai-oauth-token-file
  (expand-file-name ".cache/gptel-xai/xai-oauth-token"
                    user-emacs-directory))

(defcustom gptel-xai-oauth-login-method 'authorization-code
  "OAuth login method used by `gptel-xai-oauth-login'.

The `authorization-code' method uses OAuth 2.0 Authorization Code
Flow with PKCE and a local callback.  It is not supported when
Emacs is running over SSH.  The `device' method uses OAuth 2.0
Device Authorization Grant."
  :type '(choice (const :tag "Authorization Code Flow with PKCE" authorization-code)
                 (const :tag "Device Authorization Grant" device))
  :group 'gptel)

(defconst gptel--xai-oauth-redirect-port 56121)
(defconst gptel--xai-oauth-redirect-timeout 300)
(defconst gptel--xai-oauth-redirect-path "/callback")

;;;; xAI OAuth backend
(cl-defstruct (gptel-xai-oauth (:constructor gptel--make-xai-oauth)
                               (:copier nil)
                               (:include gptel-openai))
  token)

;;;; xAI OAuth methods
;;;;; xAI device-based OAuth

(defconst gptel--xai-oauth-poll-interval 2)
(defconst gptel--xai-oauth-poll-timeout 30)

(defun gptel--xai-oauth-poll-token (device-code)
  "Poll for a device authorization token.

Polls xAI with DEVICE-CODE until an access token is returned, a
terminal error occurs, or the request times out."
  (let ((deadline (+ (float-time) gptel--xai-oauth-poll-timeout))
        response)
    (while (and (not response)
                (< (float-time) deadline))
      (setq response
            (gptel--url-retrieve
                (concat gptel--xai-oauth-url "/oauth2/token")
              :method 'post
              :data (url-build-query-string
                     `(("grant_type"  "urn:ietf:params:oauth:grant-type:device_code")
                       ("device_code" ,device-code)
                       ("client_id"   ,gptel--xai-oauth-client-id)))
              :content-type "application/x-www-form-urlencoded"
              :headers `(("User-Agent" . ,(format "Emacs %s" emacs-version)))))
      (cond
       ((plist-get response :access_token) response)
       ((plist-get response :error)
        (let ((err (plist-get response :error)))
          (if (equal err "authorization_pending")
              (progn
                (setq response nil)
                (with-temp-message
                    (format "Waiting for xAI to authenticate (-%d seconds...)"
                            (max 0 (truncate (- deadline (float-time)))))
                  (sleep-for gptel--xai-oauth-poll-interval)))
            (user-error "%s"
                        (or (plist-get response :error_description)
                            (format "%s" err)
                            "xAI OAuth device authorization failed")))))
       (t
        (setq response nil)
        (with-temp-message
            (format "Waiting for xAI to authenticate (-%d seconds...)"
                    (max 0 (truncate (- deadline (float-time)))))
          (sleep-for gptel--xai-oauth-poll-interval)))))
    (or response
        (user-error "Timed out waiting for xAI OAuth device authorization"))))

(defun gptel--xai-oauth-login-with-device-code (backend)
  "Authenticate BACKEND using xAI Device Authorization Grant."
  (pcase-let* (((map :device_code :user_code :verification_uri)
                (gptel--url-retrieve
                    (concat gptel--xai-oauth-url "/oauth2/device/code")
                  :method 'post
                  :data (url-build-query-string
                         `(("client_id" ,gptel--xai-oauth-client-id)
                           ("scope"     "openid profile email offline_access grok-cli:access api:access")))
                  :content-type "application/x-www-form-urlencoded"
                  :headers `(("User-Agent" . ,(format "Emacs %s" emacs-version))))))
    (unless (and device_code user_code verification_uri)
      (user-error "Failed to initiate xAI device authorization"))
    (gptel-oauth--device-auth-prompt user_code verification_uri)
    (let ((token-plist (gptel--xai-oauth-poll-token device_code)))
      (gptel--xai-oauth-persist backend token-plist))))

;;;;; xAI authorization-code-based OAuth

(defun gptel--xai-oauth-authorization-url (redirect-uri verifier state)
  "Return an xAI authorization URL for REDIRECT-URI.

VERIFIER is used to derive the PKCE code challenge.  STATE is
included in the authorization request and checked in the callback."
  (concat
   gptel--xai-oauth-url "/oauth2/authorize?"
   (url-build-query-string
    `(("response_type" "code")
      ("client_id" ,gptel--xai-oauth-client-id)
      ("redirect_uri" ,redirect-uri)
      ("scope" "openid profile email offline_access grok-cli:access api:access")
      ("code_challenge" ,(gptel-oauth--generate-code-challenge verifier))
      ("code_challenge_method" "S256")
      ("state" ,state)))))

(defun gptel--xai-oauth-callback-request (request)
  "Parse callback REQUEST and return a plist with :path and :query."
  (when (string-match "\\`GET \\([^ ]+\\) HTTP/" request)
    (let* ((target (match-string 1 request))
           (query-start (string-search "?" target))
           (path (if query-start
                     (substring target 0 query-start)
                   target))
           (query (and query-start
                       (substring target (1+ query-start)))))
      (list :path path
            :query (and query (url-parse-query-string query))))))

(defun gptel--xai-oauth-send-callback-response (process status title body)
  "Send PROCESS an HTTP response with STATUS, TITLE and BODY."
  (let ((payload (format "<!doctype html><meta charset=\"utf-8\"><title>%s</title><p>%s</p>"
                         title body)))
    (process-send-string
     process
     (format "HTTP/1.1 %s %s\r\nContent-Type: text/html; \
charset=utf-8\r\nContent-Length: %d\r\nConnection: close\r\n\r\n%s"
             status title (string-bytes payload) payload))))

(defun gptel--xai-oauth-read-code (authorization-url state)
  "Open AUTHORIZATION-URL and wait for a localhost callback matching STATE."
  (when (or (getenv "SSH_CLIENT")
            (getenv "SSH_CONNECTION")
            (getenv "SSH_TTY"))
    (user-error
     (concat "xAI authorization-code login requires a local browser "
             "callback and is not supported over SSH.  Set "
             "`gptel-xai-oauth-login-method' to `device' and retry")))
  (let ((deadline (+ (float-time) gptel--xai-oauth-redirect-timeout))
        code error server)
    (cl-labels
        ((finish (process status title body &optional result failure)
           (gptel--xai-oauth-send-callback-response process status title body)
           (when result (setq code result))
           (when failure (setq error failure))
           (delete-process process))
         (filter (process string)
           (let ((request (concat (or (process-get process :gptel-request) "")
                                  string)))
             (process-put process :gptel-request request)
             (when (string-match-p "\r\n\r\n" request)
               (pcase-let* ((`(:path ,path :query ,query)
                             (gptel--xai-oauth-callback-request request))
                            (callback-state (cadr (assoc "state" query)))
                            (callback-code (cadr (assoc "code" query)))
                            (callback-error (cadr (assoc "error" query)))
                            (callback-error-description
                             (cadr (assoc "error_description" query))))
                 (cond
                  ((not (equal path gptel--xai-oauth-redirect-path))
                   (finish process "404" "Not Found"
                           "This is not an xAI OAuth callback."))
                  (callback-error
                   (finish process "400" "xAI OAuth Error"
                           "xAI OAuth authorization failed.  You may close this tab."
                           nil
                           (or callback-error-description callback-error)))
                  ((not (equal callback-state state))
                   (finish process "400" "xAI OAuth Error"
                           "xAI OAuth state did not match.  You may close this tab."
                           nil "xAI OAuth state did not match"))
                  (callback-code
                   (finish process "200" "xAI OAuth Complete"
                           "xAI OAuth authorization succeeded.  You may close this tab."
                           callback-code))
                  (t
                   (finish process "400" "xAI OAuth Error"
                           "xAI OAuth callback did not include a code.  You may close this tab."
                           nil "xAI OAuth callback did not include a code"))))))))
      (unwind-protect
          (progn
            (setq server
                  (make-network-process
                   :name "gptel-xai-oauth-callback"
                   :server t
                   :host "127.0.0.1"
                   :service gptel--xai-oauth-redirect-port
                   :filter #'filter
                   :noquery t))
            (message "xAI OAuth authorization URL: %s" authorization-url)
            (ignore-errors (gui-set-selection 'CLIPBOARD authorization-url))
            (read-from-minibuffer
             (format "xAI OAuth URL copied to clipboard.  \
Press ENTER to open the authorization page.  \
If your browser does not open automatically, browse to %s: "
                     authorization-url))
            (browse-url authorization-url)
            (while (and (not code) (not error) (< (float-time) deadline))
              (accept-process-output nil 1))
            (cond
             (code code)
             (error (user-error "%s" error))
             (t (user-error "Timed out waiting for xAI OAuth callback"))))
        (when (process-live-p server)
          (delete-process server))))))

(defun gptel--xai-oauth-login-with-authorization-code (backend)
  "Authenticate BACKEND using xAI Authorization Code Flow with PKCE."
  (let* ((redirect-uri (format "http://127.0.0.1:%d%s"
                               gptel--xai-oauth-redirect-port
                               gptel--xai-oauth-redirect-path))
         (verifier (gptel-oauth--generate-code-verifier))
         (state (secure-hash 'sha256 (format "%s%s" (float-time) (random))))
         (authorization-url
          (gptel--xai-oauth-authorization-url redirect-uri verifier state))
         (code (gptel--xai-oauth-read-code authorization-url state))
         (token-plist
          (gptel--url-retrieve (concat gptel--xai-oauth-url "/oauth2/token")
            :method 'post
            :data (url-build-query-string
                   `(("grant_type"    "authorization_code")
                     ("client_id"     ,gptel--xai-oauth-client-id)
                     ("code"          ,code)
                     ("code_verifier" ,verifier)
                     ("redirect_uri"  ,redirect-uri)))
            :content-type "application/x-www-form-urlencoded")))
    (gptel--xai-oauth-persist backend token-plist)))

;;;; xAI OAuth login and token handling

(defun gptel--xai-oauth-default-backend ()
  "Return the current or first registered xAI OAuth backend."
  (cond
   ((gptel-xai-oauth-p gptel-backend)
    gptel-backend)
   ((cdr (cl-find-if #'gptel-xai-oauth-p gptel--known-backends
                     :key #'cdr)))
   (t (user-error "No xAI OAuth backend found.  \
Please set one up with `gptel-make-xai-oauth' first"))))

(defun gptel-xai-oauth-login (&optional backend method)
  "Authenticate BACKEND using xAI OAuth.

If BACKEND is nil, use `gptel-backend' when it is an xAI OAuth
backend, otherwise use the first registered xAI OAuth backend.
METHOD can be `authorization-code' for OAuth 2.0 Authorization
Code Flow with PKCE or `device' for OAuth 2.0 Device
Authorization Grant.  If METHOD is nil, use
`gptel-xai-oauth-login-method'."
  (interactive (list (gptel--xai-oauth-default-backend)))
  (unless backend (setq backend (gptel--xai-oauth-default-backend)))
  (unless (gptel-xai-oauth-p backend)
    (user-error "%s is not an xAI OAuth backend" (gptel-backend-name backend)))
  (let ((token-plist
         (pcase (or method gptel-xai-oauth-login-method)
           ('authorization-code
            (gptel--xai-oauth-login-with-authorization-code backend))
           ('device
            (gptel--xai-oauth-login-with-device-code backend))
           (login-method
            (user-error "Unknown xAI OAuth login method: %S" login-method)))))
    (when (and (called-interactively-p 'interactive)
               (plist-get token-plist :access_token))
      (message "Successfully logged in to xAI OAuth."))
    token-plist))

(defun gptel--xai-oauth-persist (backend token-plist)
  "Persist TOKEN-PLIST for BACKEND.

Normalizes TOKEN-PLIST for storage, writes it to disk, and stores
it in BACKEND."
  (pcase-let (((map :access_token :expires_in :id_token :refresh_token) token-plist))
    (unless access_token
      (user-error "xAI OAuth Authentication failed"))
    (let ((token-processed
           (list :expires_at (+ (float-time) (or expires_in 3600))
                 :access_token access_token
                 :refresh_token refresh_token
                 :id_token (and id_token (gptel-oauth--jwt-payload id_token)))))
      (gptel-oauth--write-token gptel--xai-oauth-token-file token-processed)
      (setf (gptel-xai-oauth-token backend) token-processed)
      token-plist)))

(defun gptel--xai-oauth-refresh (backend refresh-token)
  "Refresh BACKEND using REFRESH-TOKEN.

Returns the refreshed token payload after persisting it."
  (gptel--xai-oauth-persist
   backend
   (gptel--url-retrieve (concat gptel--xai-oauth-url "/oauth2/token")
     :method 'post
     :data (url-build-query-string
            `(("grant_type"    "refresh_token")
              ("refresh_token" ,refresh-token)
              ("client_id"     ,gptel--xai-oauth-client-id)))
     :content-type "application/x-www-form-urlencoded")))

(defun gptel--xai-oauth-ensure (&optional backend)
  "Ensure BACKEND has a valid xAI OAuth token.

If BACKEND is nil, use `gptel-backend'.  Restore, refresh, or
reauthenticate as needed."
  (unless backend (setq backend gptel-backend))
  (unless (gptel-xai-oauth-token backend)
    (if-let* ((token-plist (gptel-oauth--read-token
                            gptel--xai-oauth-token-file)))
        (setf (gptel-xai-oauth-token backend) token-plist)
      (gptel-xai-oauth-login backend)))
  
  (let ((token-plist (gptel-xai-oauth-token backend)))
    (if-let* ((expiry (plist-get token-plist :expires_at))
              ((> expiry (+ (float-time) 10))))
        t
      (if-let* ((refresh (plist-get token-plist :refresh_token)))
          (gptel--xai-oauth-refresh backend refresh)
        (gptel-xai-oauth-login backend)))))

;;;; OAuth backend management

(defun gptel--xai-oauth-header (_info)
  "Return authentication headers for the current xAI OAuth backend.

_INFO is ignored.  Ensures `gptel-backend' has a valid token
before constructing the headers."
  (gptel--xai-oauth-ensure gptel-backend)
  (let* ((token (gptel-xai-oauth-token gptel-backend))
         (key (plist-get token :access_token)))
    `(("Authorization" . ,(concat "Bearer " key)))))

;;;###autoload
(cl-defun gptel-make-xai-oauth
    (name &key curl-args (stream t) request-params
          (header #'gptel--xai-oauth-header)
          (host "api.x.ai")
          (protocol "https")
          (endpoint "/v1/chat/completions")
          (models
           '((grok-4.5
              :description "Most advanced flagship model, leading in agentic tool calling and instruction following capabilities."
              :capabilities (tool-use json media reasoning)
              :mime-types ("image/jpeg" "image/png" "image/gif" "image/webp")
              :context-window 500
              :input-cost 2
              :output-cost 6)
             (grok-4.3
              :description "Advanced flagship model, leading in agentic tool calling and instruction following capabilities."
              :capabilities (tool-use json media reasoning)
              :mime-types ("image/jpeg" "image/png" "image/gif" "image/webp")
              :context-window 1000
              :input-cost 1.25
              :output-cost 2.5)
             (grok-build-0.1
              :description "xAI's fast coding model trained specifically for agentic coding. Currently in early access."
              :capabilities (tool-use json media reasoning)
              :mime-types ("image/jpeg" "image/png" "image/gif" "image/webp")
              :context-window 256
              :input-cost 1
              :output-cost 2)
             grok-3)))
  "Register a SuperGrok / xAI OAuth backend for gptel with NAME.

This backend uses xAI OAuth tokens (not xAI API keys) to access
SuperGrok / X Premium+ subscriptions.  Run `gptel-xai-oauth-login'
once to authenticate.

For keyword argument meanings, see `gptel-make-openai'."
  (declare (indent 1))
  (let ((backend (gptel--make-xai-oauth
                  :curl-args curl-args
                  :name name
                  :host host
                  :header header
                  :key nil
                  :models (gptel--process-models models)
                  :protocol protocol
                  :endpoint endpoint
                  :stream stream
                  :request-params request-params
                  :url (if protocol
                           (concat protocol "://" host endpoint)
                         (concat host endpoint)))))
    (prog1 backend
      (setf (alist-get name gptel--known-backends nil nil #'equal)
            backend))))

(provide 'gptel-xai-oauth)
;;; gptel-xai-oauth.el ends here
