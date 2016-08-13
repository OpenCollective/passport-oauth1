function SessionStore(options) {
  if (!options.key) { throw new TypeError('Session-based request token store requires a session key'); }
  console.log("requesttoken/session.js: setting session key", options.key);
  this._key = options.key;
}

SessionStore.prototype.get = function(req, token, cb) {
  if (!req.session) { return cb(new Error('OAuth authentication requires session support. Did you forget to use express-session middleware?')); }

  // Bail if the session does not contain the request token and corresponding
  // secret.  If this happens, it is most likely caused by initiating OAuth
  // from a different host than that of the callback endpoint (for example:
  // initiating from 127.0.0.1 but handling callbacks at localhost).
  if (!req.session[this._key]) {
    console.log("requesttoken/session.js: Failed to find request token in session, dumping session contents:", req.session);
    return cb(new Error(`Failed to find request token ${this._key} in session`));
  }

  var tokenSecret = req.session[this._key].oauth_token_secret;
  return cb(null, tokenSecret);
};

SessionStore.prototype.set = function(req, token, tokenSecret, cb) {
  if (!req.session) {
    return cb(new Error('OAuth authentication requires session support. Did you forget to use express-session middleware?'));
  }

  if (!req.session[this._key]) {
    console.log("requesttoken/session.js: Adding key to session. Original session contents:", req.session);
    console.log("requesttoken/session.js: Key:", this._key);
    req.session[this._key] = {};
  }
  console.log("requesttoken/session.js: Adding token with key", token);
  req.session[this._key].oauth_token = token;
  req.session[this._key].oauth_token_secret = tokenSecret;
  cb();
};

SessionStore.prototype.destroy = function(req, token, cb) {
  console.log("requesttoken/session.js: Removing token from session", req.session[this._key].oauth_token);
  delete req.session[this._key].oauth_token;
  delete req.session[this._key].oauth_token_secret;
  if (Object.keys(req.session[this._key]).length === 0) {
    console.log("requesttoken/session.js: Removing key from session", this._key);
    delete req.session[this._key];
  }
  cb();
};


module.exports = SessionStore;
