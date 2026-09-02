module example.internal/pqc-pdf-sign/server

go 1.27.0

// Receiver API (Rencana V1 §17). Built on the BSD digitorus/pdfsign library
// only; digitorus/pdfsigner (GPL) is studied as a reference, not imported
// (Rencana V1 §3.2). Implementation lands in milestone M6.
require example.internal/pqc-pdf-sign/core v0.0.0

replace example.internal/pqc-pdf-sign/core => ../core
