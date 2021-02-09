# Ntlm
This is experimental implementation of NTLMv2 written in c#.
Primary use is for HTTP in cases when HttpClient does not work for whatever reason. 

It is still somewhat incomplete and based on v32 https://docs.microsoft.com/en-us/openspecs/windows_protocols/ms-nlmp/

This does not depend on any particular version and it does not change HttpClient's internals (nor HttpHandler).
Instead it wraps the response and in case of `401` it sets `Authorization` directly and tries again.

It supports plain NTLM as well as Negotiate/SPNEGO as described in https://tools.ietf.org/html/rfc455

If you want to try it, modify Program.cs with your credentials and URI and have fun.
Alternatively, export CREDENTIALS='domain\user:password'. 

`AsnWriter` was added in .NET 5.0 and it is used to write SPNEGO header. Plain NTLM should work without it e.g. be portable to older .NET version. 
