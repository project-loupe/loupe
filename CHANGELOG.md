# Changelog

## v0.1 — 2026-09-07

First release of Loupe, a security-scanning harness for source repositories.
Initial development established the server, workers, and admin CLI; mutual TLS;
encrypted storage; scheduled scans; Claude and Codex agents; finding
deduplication and verification; and GitHub, email, or manual reporting.

- Fix formatting and lint failures in CI ([#3]).
- Preserve base64 padding when loading deployment secrets ([#4]).
- Fix DNS resolution inside agent sandboxes ([#6]).
- Fix documentation formatting flagged by Clippy ([#7]).
- Add Docker deployment support for servers and workers ([#8]).
- Bundle trusted TLS roots so GitHub reporting works out of the box ([#9]).
- Add token and server certificate rotation, and retries for failed reports ([#10]).
- Improve per-finding GitHub reports, including PoCs and suggested fixes ([#11]).
- Add a configurable verification default for newly registered repositories ([#12]).
- Add worker configuration files and configurable agent settings ([#13]).
- Improve source discovery across project layouts, exclusions, and large files ([#14]).
- Terminate agent subprocesses when their requests time out ([#15]).
- Restrict permissions on worker credential bundles ([#16]).
- Show the newest results last in CLI lists ([#17]).
- Prioritize verification jobs over new scans ([#18]).
- Remove severity prefixes from GitHub issue titles ([#19]).
- Create namespaced severity labels for GitHub reports ([#20]).
- Document LLM usage costs and the impact of scanning large repositories ([#21]).
- Recover missing verification jobs and discard partial findings from failed scans ([#23]).
- Support Codex API-key authentication in workers and deployment helpers ([#24]).
- Discover in-repository Cargo packages outside workspace membership ([#25]).
- Extend verification retries to stalled and deadline-dismissed findings ([#26]).
- Include the reviewed revision in reports and document the project Discord ([#27]).
- Refresh repositories before checkout and verify findings at their original revision ([#28]).
- Add .NET project support to source discovery ([#29]).
- Centralize job and finding lifecycle transitions in storage ([#30]).
- Include server rejection reasons in worker errors ([#31]).
- Add configurable row limits to CLI list commands ([#32]).
- Allow explicit agent selection for scan and verification jobs ([#33]).
- Harden agent sandboxes, credentials, and tool boundaries against prompt injection ([#34]).
- Allow scans to proceed with unfollowed submodules and symbolic links ([#39]).
- Add a local web dashboard for repository, job, and finding management ([#44]).
- Isolate worker network access and add role-specific Debian host setup ([#55]).
- Include the MIT and Apache 2.0 license texts ([#56]).
- Move the server container to Debian Trixie ([#57]).

[#3]: https://github.com/project-loupe/loupe/pull/3
[#4]: https://github.com/project-loupe/loupe/pull/4
[#6]: https://github.com/project-loupe/loupe/pull/6
[#7]: https://github.com/project-loupe/loupe/pull/7
[#8]: https://github.com/project-loupe/loupe/pull/8
[#9]: https://github.com/project-loupe/loupe/pull/9
[#10]: https://github.com/project-loupe/loupe/pull/10
[#11]: https://github.com/project-loupe/loupe/pull/11
[#12]: https://github.com/project-loupe/loupe/pull/12
[#13]: https://github.com/project-loupe/loupe/pull/13
[#14]: https://github.com/project-loupe/loupe/pull/14
[#15]: https://github.com/project-loupe/loupe/pull/15
[#16]: https://github.com/project-loupe/loupe/pull/16
[#17]: https://github.com/project-loupe/loupe/pull/17
[#18]: https://github.com/project-loupe/loupe/pull/18
[#19]: https://github.com/project-loupe/loupe/pull/19
[#20]: https://github.com/project-loupe/loupe/pull/20
[#21]: https://github.com/project-loupe/loupe/pull/21
[#23]: https://github.com/project-loupe/loupe/pull/23
[#24]: https://github.com/project-loupe/loupe/pull/24
[#25]: https://github.com/project-loupe/loupe/pull/25
[#26]: https://github.com/project-loupe/loupe/pull/26
[#27]: https://github.com/project-loupe/loupe/pull/27
[#28]: https://github.com/project-loupe/loupe/pull/28
[#29]: https://github.com/project-loupe/loupe/pull/29
[#30]: https://github.com/project-loupe/loupe/pull/30
[#31]: https://github.com/project-loupe/loupe/pull/31
[#32]: https://github.com/project-loupe/loupe/pull/32
[#33]: https://github.com/project-loupe/loupe/pull/33
[#34]: https://github.com/project-loupe/loupe/pull/34
[#39]: https://github.com/project-loupe/loupe/pull/39
[#44]: https://github.com/project-loupe/loupe/pull/44
[#55]: https://github.com/project-loupe/loupe/pull/55
[#56]: https://github.com/project-loupe/loupe/pull/56
[#57]: https://github.com/project-loupe/loupe/pull/57
