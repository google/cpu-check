// Copyright 2020 Google LLC
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//      http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include "utils.h"

#include <sys/time.h>
#include <unistd.h>

#include "log.h"

static const std::string host_name = []() {
  char host[256];
  gethostname(host, sizeof(host));
  const std::string h(host);
  size_t k = h.find('.');
  if (k == std::string::npos) return h;
  return h.substr(0, k);
}();

double TimeInSeconds() {
  struct timeval tv;
  gettimeofday(&tv, nullptr);
  return ((tv.tv_sec * 1e6) + tv.tv_usec) / 1e6;
}

std::string Json(const std::string& field, int v) {
  return "\"" + field + "\": " + std::to_string(v);
}

std::string Json(const std::string& field, uint64_t v) {
  return "\"" + field + "\": " + std::to_string(v);
}

std::string Json(const std::string& field, double v) {
  return "\"" + field + "\": " + std::to_string(v);
}

std::string JsonBool(const std::string& field, bool v) {
  return "\"" + field + "\": " + (v ? "true" : "false");
}

std::string Json(const std::string& field, const std::string& v) {
  return "\"" + field + "\": \"" + v + "\"";
}

std::string JsonRecord(const std::string& name, const std::string& v) {
  return "\"" + name + "\": { " + v + " }";
}

// Emits null field.
std::string JsonNull(const std::string& field) {
  return "\"" + field + "\": null";
}

// Returns host and timestamp fields. ToDo: probably add a run id.
std::string JTag() {
  const uint64_t t = TimeInSeconds() * 1e6;
  return Json("host", host_name) + ", " + Json("t_us", t);
}

// Emits a run status record.
std::string Jstat(const std::string& v) {
  return "{ " + JsonRecord("stat", v) + ", " + JTag() + " }";
}
