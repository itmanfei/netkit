#pragma once
#include <netkit/io_context_pool.h>

#include <stop_token>
#include <string>

using namespace netkit;

void TestTcpListener(std::stop_token st, IoContextPool& pool,
                     const std::string& address, std::uint16_t port);

void TestHttpRouter(std::stop_token st);

void TestHttpServer(std::stop_token st, IoContextPool& pool,
                    const std::string& address, std::uint16_t port);
