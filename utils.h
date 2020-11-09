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

#ifndef UTILS_H_
#define UTILS_H_

#include <string>

#include "absl/strings/string_view.h"

double TimeInSeconds();

std::string HexData(const char* s, uint32_t l);
std::string HexStr(const std::string& s);

std::string Json(const std::string& field, int v);
std::string Json(const std::string& field, uint64_t v);
std::string Json(const std::string& field, double v);
std::string JsonBool(const std::string& field, bool v);
std::string Json(const std::string& field, absl::string_view v);
std::string JsonRecord(const std::string& name, absl::string_view v);

// Emits null field.
std::string JsonNull(const std::string& field);

// Returns host and timestamp fields. ToDo: probably add a run id.
std::string JTag();

// Emits a run status record.
std::string Jstat(const std::string& v);

#endif  // UTILS_H_
