package api

import "net/http"

// contentSecurityPolicy keeps every page to its own origin. Inline <script>
// and <style> stay allowed — each page is one self-contained HTML string —
// and connect-src stays open because the public pages let the reader point
// them at another verification server ("Alamat server").
const contentSecurityPolicy = "default-src 'self'; " +
	"script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; " +
	"img-src 'self' data: blob:; font-src 'self' data:; connect-src 'self' http: https:; " +
	"object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'"

// securityHeaders sets the browser hardening headers on every response.
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		h.Set("Content-Security-Policy", contentSecurityPolicy)
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		next.ServeHTTP(w, r)
	})
}
