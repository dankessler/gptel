;;; gptel-xai-oauth.el --- SuperGrok subscription support  -*- lexical-binding: t; -*-

;; Copyright (C) 2026  Karthik Chikmagalur
;; SPDX-License-Identifier: GPL-3.0-or-later

;;; Commentary:

;; Authenticate with xAI using the OAuth authorization-code flow and use a
;; SuperGrok subscription with gptel.  This is separate from the API-key based
;; `gptel-make-xai' backend.

;;; Code:
(require 'cl-lib)
(require 'gptel-openai)
(require 'gptel-oauth)

;; These are the public OAuth client settings used by OpenCode's xAI
;; integration.  A client secret is intentionally not used: PKCE authenticates
;; the authorization-code exchange for this native application.
(defconst gptel--xai-oauth-client-id "xai-cli")
(defconst gptel--xai-oauth-authorize-url "https://accounts.x.ai/oauth2/auth")
(defconst gptel--xai-oauth-token-url "https://accounts.x.ai/oauth2/token")

(defvar gptel--xai-oauth-token-file
  (expand-file-name ".cache/gptel-xai/xai-oauth-token"
                    user-emacs-directory))

(defconst gptel--xai-oauth-redirect-port 1455)
(defconst gptel--xai-oauth-redirect-path "/auth/callback")
(defconst gptel--xai-oauth-redirect-timeout 300)

(cl-defstruct (gptel-xai-oauth (:constructor gptel--make-xai-oauth)
                               (:copier nil)
                               (:include gptel-openai))
  token)

(defun gptel--xai-oauth-authorization-url (redirect-uri verifier state)
  "Build the xAI authorization URL for REDIRECT-URI.

VERIFIER supplies the PKCE challenge and STATE protects the callback."
  (concat
   gptel--xai-oauth-authorize-url "?"
   (url-build-query-string
    `(("response_type" "code")
      ("client_id" ,gptel--xai-oauth-client-id)
      ("redirect_uri" ,redirect-uri)
      ("scope" "openid profile email offline_access")
      ("code_challenge" ,(gptel-oauth--generate-code-challenge verifier))
      ("code_challenge_method" "S256")
      ("state" ,state)))))

(defun gptel--xai-oauth-callback-request (request)
  "Parse callback REQUEST into a plist containing its path and query."
  (when (string-match "\\`GET \\([^ ]+\\) HTTP/" request)
    (let* ((target (match-string 1 request))
           (query-start (string-search "?" target)))
      (list :path (if query-start (substring target 0 query-start) target)
            :query (and query-start
                        (url-parse-query-string
                         (substring target (1+ query-start))))))))

(defun gptel--xai-oauth-send-callback-response (process status title body)
  "Send PROCESS an HTTP response with STATUS, TITLE, and BODY."
  (let ((payload (format "<!doctype html><meta charset=\"utf-8\"><title>%s</title><p>%s</p>"
                         title body)))
    (process-send-string
     process
     (format "HTTP/1.1 %s %s\r\nContent-Type: text/html; charset=utf-8\r\n\
Content-Length: %d\r\nConnection: close\r\n\r\n%s"
             status title (string-bytes payload) payload))))

(defun gptel--xai-oauth-read-code (authorization-url state)
  "Open AUTHORIZATION-URL and wait for a callback matching STATE."
  (when (or (getenv "SSH_CLIENT") (getenv "SSH_CONNECTION")
            (getenv "SSH_TTY"))
    (user-error "SuperGrok OAuth login requires a local browser callback and is not supported over SSH"))
  (let ((deadline (+ (float-time) gptel--xai-oauth-redirect-timeout))
        code error server)
    (cl-labels
        ((finish (process status title body &optional result failure)
           (gptel--xai-oauth-send-callback-response
            process status title body)
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
                           "This is not a SuperGrok OAuth callback."))
                  (callback-error
                   (finish process "400" "SuperGrok OAuth Error"
                           "Authorization failed.  You may close this tab."
                           nil (or callback-error-description callback-error)))
                  ((not (equal callback-state state))
                   (finish process "400" "SuperGrok OAuth Error"
                           "OAuth state did not match.  You may close this tab."
                           nil "SuperGrok OAuth state did not match"))
                  (callback-code
                   (finish process "200" "SuperGrok OAuth Complete"
                           "Authorization succeeded.  You may close this tab."
                           callback-code))
                  (t
                   (finish process "400" "SuperGrok OAuth Error"
                           "The callback contained no code.  You may close this tab."
                           nil "SuperGrok OAuth callback did not include a code"))))))))
      (unwind-protect
          (progn
            (setq server
                  (make-network-process
                   :name "gptel-xai-oauth-callback" :server t
                   :host "localhost" :service gptel--xai-oauth-redirect-port
                   :filter #'filter :noquery t))
            (message "SuperGrok OAuth authorization URL: %s" authorization-url)
            (ignore-errors (gui-set-selection 'CLIPBOARD authorization-url))
            (read-from-minibuffer
             (format "SuperGrok OAuth URL copied.  Press ENTER to open it (or browse to %s): "
                     authorization-url))
            (browse-url authorization-url)
            (while (and (not code) (not error) (< (float-time) deadline))
              (accept-process-output nil 1))
            (cond (code code)
                  (error (user-error "%s" error))
                  (t (user-error "Timed out waiting for SuperGrok OAuth callback"))))
        (when (process-live-p server) (delete-process server))))))

(defun gptel--xai-oauth-persist (backend token-plist &optional old-refresh-token)
  "Normalize TOKEN-PLIST, persist it, and install it in BACKEND.

OLD-REFRESH-TOKEN is retained when a refresh response does not rotate it."
  (let ((access-token (plist-get token-plist :access_token))
        (expires-in (plist-get token-plist :expires_in))
        (refresh-token (or (plist-get token-plist :refresh_token)
                           old-refresh-token)))
    (unless (and access-token expires-in refresh-token)
      (user-error "SuperGrok OAuth authentication failed: %S" token-plist))
    (let ((token (list :expires_at (+ (float-time) expires-in)
                       :access_token access-token
                       :refresh_token refresh-token)))
      (gptel-oauth--write-token gptel--xai-oauth-token-file token)
      (setf (gptel-xai-oauth-token backend) token)
      token-plist)))

(defun gptel-xai-oauth-login (&optional backend)
  "Authenticate a SuperGrok OAuth BACKEND using authorization code and PKCE."
  (interactive)
  (unless backend
    (setq backend
          (if (gptel-xai-oauth-p gptel-backend) gptel-backend
            (cdr (cl-find-if #'gptel-xai-oauth-p gptel--known-backends
                             :key #'cdr)))))
  (unless (gptel-xai-oauth-p backend)
    (user-error "No SuperGrok OAuth backend found; create one with `gptel-make-xai-oauth'"))
  (let* ((redirect-uri (format "http://localhost:%d%s"
                               gptel--xai-oauth-redirect-port
                               gptel--xai-oauth-redirect-path))
         (verifier (gptel-oauth--generate-code-verifier))
         (state (secure-hash 'sha256 (format "%s%s" (float-time) (random))))
         (code (gptel--xai-oauth-read-code
                (gptel--xai-oauth-authorization-url
                 redirect-uri verifier state)
                state))
         (response
          (gptel--url-retrieve gptel--xai-oauth-token-url
            :method 'post
            :data (url-build-query-string
                   `(("grant_type" "authorization_code")
                     ("client_id" ,gptel--xai-oauth-client-id)
                     ("code" ,code) ("code_verifier" ,verifier)
                     ("redirect_uri" ,redirect-uri)))
            :content-type "application/x-www-form-urlencoded")))
    (prog1 (gptel--xai-oauth-persist backend response)
      (when (called-interactively-p 'interactive)
        (message "Successfully logged in with SuperGrok.")))))

(defun gptel--xai-oauth-refresh (backend refresh-token)
  "Refresh BACKEND using REFRESH-TOKEN."
  (gptel--xai-oauth-persist
   backend
   (gptel--url-retrieve gptel--xai-oauth-token-url
     :method 'post
     :data (url-build-query-string
            `(("grant_type" "refresh_token")
              ("refresh_token" ,refresh-token)
              ("client_id" ,gptel--xai-oauth-client-id)))
     :content-type "application/x-www-form-urlencoded")
   refresh-token))

(defun gptel--xai-oauth-ensure (backend)
  "Restore or obtain a valid OAuth token for BACKEND."
  (unless (gptel-xai-oauth-token backend)
    (if-let* ((token (gptel-oauth--read-token gptel--xai-oauth-token-file)))
        (setf (gptel-xai-oauth-token backend) token)
      (gptel-xai-oauth-login backend)))
  (let ((token (gptel-xai-oauth-token backend)))
    (unless (and-let* ((expiry (plist-get token :expires_at)))
              (> expiry (+ (float-time) 10)))
      (if-let* ((refresh-token (plist-get token :refresh_token)))
          (gptel--xai-oauth-refresh backend refresh-token)
        (gptel-xai-oauth-login backend)))))

(defun gptel--xai-oauth-header (_info)
  "Return a bearer authentication header for a SuperGrok request."
  (gptel--xai-oauth-ensure gptel-backend)
  `(("Authorization" . ,(concat
                          "Bearer "
                          (plist-get (gptel-xai-oauth-token gptel-backend)
                                     :access_token)))))

;;;###autoload
(cl-defun gptel-make-xai-oauth
    (name &key curl-args stream request-params
          (header #'gptel--xai-oauth-header)
          (host "api.x.ai") (protocol "https")
          (endpoint "/v1/chat/completions")
          (models '(grok-4.5 grok-4.3 grok-build-0.1)))
  "Register a SuperGrok subscription OAuth backend named NAME.

This backend uses a SuperGrok subscription rather than an xAI API key.
Authentication is performed automatically, or can be started with
`gptel-xai-oauth-login'.  Remaining keyword arguments have the same meanings
as for `gptel-make-openai'."
  (declare (indent 1))
  (let ((backend (gptel--make-xai-oauth
                  :name name :host host :header header :key nil
                  :models (gptel--process-models models)
                  :protocol protocol :endpoint endpoint :stream stream
                  :request-params request-params :curl-args curl-args
                  :url (if protocol (concat protocol "://" host endpoint)
                         (concat host endpoint)))))
    (setf (alist-get name gptel--known-backends nil nil #'equal) backend)
    backend))

(provide 'gptel-xai-oauth)
;;; gptel-xai-oauth.el ends here
