module github.com/restlesshq/go

// Go 1.23 is the minimum: DefaultRouteResolver reads http.Request.Pattern,
// added in 1.23 alongside the enhanced ServeMux routing patterns.
//
// A //go:build go1.23 split was tried first and removed, because the tag
// keys off the LANGUAGE version in THIS go.mod rather than the consumer's
// toolchain - so declaring `go 1.21` would have disabled r.Pattern for
// everyone, including users on Go 1.26, rather than degrading gracefully.
// Users on an older toolchain should pass an explicit RouteResolver and
// pin an earlier SDK version.
go 1.23
