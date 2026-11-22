// webui_loader -- static-file fallback server.
//
// A module that brings a WebUI in its own image also brings the HTTP server: the
// module's WebUI bootstrap calls the kit's CivetWeb-based server and reports the
// port back.  When a module exposes no server of its own, the loader keeps the
// documented HTTP contract alive by serving the module's `webroot` directory
// itself: GET / resolves to webroot/index.html, every other GET is a file lookup
// confined to that directory, and writes are rejected with 404/405.
//
// The server is CivetWeb 1.16 (the library the module kit and the open edition of
// the kit both use); see third_party/civetweb/README.md for the origin.
//
#pragma once

#include <string>

namespace maplesu::payload::webui {

struct ServerConfig {
    std::string document_root;   // module webroot directory
    int port = 0;                // port the kit allocated for this session
};

class WebRootServer {
public:
    WebRootServer() = default;
    ~WebRootServer();
    WebRootServer(const WebRootServer&) = delete;
    WebRootServer& operator=(const WebRootServer&) = delete;

    // Binds 127.0.0.1:<port> and starts the serving threads.  Returns false when
    // the port cannot be bound or the document root cannot be described. The
    // loader reports that startup failure and exits without opening a browser.
    bool start(const ServerConfig& config);

    // Stops the serving threads and releases the port.
    void stop();

    bool running() const;

private:
    struct Impl;
    Impl* impl_ = nullptr;
};

}  // namespace maplesu::payload::webui
