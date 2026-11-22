// webui_loader -- static-file fallback server implementation.
//
#include "webroot_server.h"

#include <cstdio>
#include <cstring>
#include <string>
#include <vector>

#include "CivetServer.h"
#include "payload_support.h"

namespace maplesu::payload::webui {
namespace {

// Value the kit uses for "serve only, do not invent behaviour": one serving
// thread is enough for a localhost diagnostic page.
constexpr const char* kThreadCount = "1";
constexpr size_t kIndexBodyLimit = 8u * 1024u * 1024u;

// GET / is resolved explicitly so the loader's serving contract does not depend
// on the module having provided an index file through CivetWeb's own default
// resolution order.  Every other GET is a plain file lookup under the webroot:
// the handler declines it and CivetWeb serves it with its normal content-type
// mapping, keeping the contract identical to a module-served webroot.
class RootHandler final : public CivetHandler {
public:
    explicit RootHandler(std::string document_root)
        : document_root_(std::move(document_root)) {}

    bool handleGet(CivetServer* /*server*/, struct mg_connection* conn) override {
        const struct mg_request_info* request = mg_get_request_info(conn);
        const char* uri = (request != nullptr && request->local_uri != nullptr)
                              ? request->local_uri
                              : "/";
        if (std::strcmp(uri, "/") != 0) return false;

        const std::string index_path = document_root_ + "/index.html";
        std::string body;
        if (!read_file(index_path, body)) return false;
        if (body.size() > kIndexBodyLimit) return false;

        mg_printf(conn,
                  "HTTP/1.1 200 OK\r\n"
                  "Access-Control-Allow-Origin: *\r\n"
                  "Content-Type: text/html; charset=UTF-8\r\n"
                  "Content-Length: %zu\r\n"
                  "Connection: close\r\n\r\n",
                  body.size());
        mg_write(conn, body.data(), body.size());
        return true;
    }

private:
    std::string document_root_;
};

}  // namespace

struct WebRootServer::Impl {
    CivetServer* server = nullptr;
    RootHandler* handler = nullptr;
};

WebRootServer::~WebRootServer() { stop(); }

bool WebRootServer::start(const ServerConfig& config) {
    if (impl_ != nullptr) return true;
    if (config.port <= 0 || config.port > 65535 || config.document_root.empty()) return false;
    if (!is_directory(config.document_root)) return false;

    const std::string port_text = "127.0.0.1:" + std::to_string(config.port);
    const std::vector<std::string> options = {
        "listening_ports", port_text,
        "num_threads", kThreadCount,
        "document_root", config.document_root,
        "enable_directory_listing", "no",
        "error_pages", "no",
    };

    auto* impl = new Impl();
    try {
        impl->server = new CivetServer(options);
    } catch (const std::exception& exc) {
        err_printf("[webui_loader] webroot server: %s\n", exc.what());
        delete impl->server;
        delete impl;
        return false;
    }
    if (impl->server->getContext() == nullptr) {
        delete impl->server;
        delete impl;
        return false;
    }
    impl->handler = new RootHandler(config.document_root);
    impl->server->addHandler("/", *impl->handler);
    impl_ = impl;
    return true;
}

void WebRootServer::stop() {
    if (impl_ == nullptr) return;
    if (impl_->server != nullptr) {
        impl_->server->close();
        delete impl_->server;
    }
    delete impl_->handler;
    delete impl_;
    impl_ = nullptr;
}

bool WebRootServer::running() const {
    return impl_ != nullptr && impl_->server != nullptr &&
           impl_->server->getContext() != nullptr;
}

}  // namespace maplesu::payload::webui
