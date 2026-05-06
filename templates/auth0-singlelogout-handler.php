<?php
// Intentionally left empty.
// The auth0.js front-end checkSession SLO handler was removed in response
// to issue https://github.com/proudcity/wp-proudcity/issues/2150 — silent
// auth returned login_required on strict-cookie browsers and inside the
// customizer iframe, logging out healthy sessions on every refresh.
// The server-side logout() flow in WP_Auth0_LoginManager still handles
// the WP admin-bar logout link and ?SLO=1 redirects.
