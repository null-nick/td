//
// Copyright Aliaksei Levin (levlam@telegram.org), Arseny Smirnov (arseny30@gmail.com) 2014-2024
//
// Distributed under the Boost Software License, Version 1.0. (See accompanying
// file LICENSE_1_0.txt or copy at http://www.boost.org/LICENSE_1_0.txt)
//
#include "td/telegram/net/PublicRsaKeyShared.h"

#include "td/utils/algorithm.h"
#include "td/utils/format.h"
#include "td/utils/logging.h"
#include "td/utils/Slice.h"
#include "td/utils/SliceBuilder.h"
#include "td/utils/Status.h"

#include <algorithm>

namespace td {

PublicRsaKeyShared::PublicRsaKeyShared(DcId dc_id, bool is_test) : dc_id_(dc_id) {
  if (!dc_id_.is_empty()) {
    return;
  }
  auto add_pem = [this](CSlice pem) {
    auto r_rsa = mtproto::RSA::from_pem_public_key(pem);
    LOG_CHECK(r_rsa.is_ok()) << r_rsa.error() << " " << pem;

    if (r_rsa.is_ok()) {
      add_rsa(r_rsa.move_as_ok());
    }
  };

  if (is_test) {
    add_pem(
        "-----BEGIN RSA PUBLIC KEY-----\n"
        "MIIBCgKCAQEAw66UV/20T0e5G5OJQBkz8tCyc1f+EW7XZAeYeEgp/bxmKVFp0dMj\n"
        "q2ZP1pIO+6rIcl2n6sqkkdHx7sglnKaOTP6G/GgjyQOjI95GwOZLjdXJOhiHEcG/\n"
        "ePy+DJmQQiembJE1JB3YuSoK2IqzpnNLwTtX+jhhS7KqefPvCSDVd5KPfmibe1sK\n"
        "GopI2p1+TCjyqPGq7aIqxNoFMkwctnU4rf4awyAbNKhRibB2Xmx5/0Q0M4N7VA1i\n"
        "lb+e6VuM2nCYaMRQvpcwyfzHRCAREpr7RRh8KhkTpJdHCelmaGXE8GBn6YG/V5UK\n"
        "A5W0XDpzIv02932AP/l4l7wA1Wh6PLV10QIDAQAB\n"
        "-----END RSA PUBLIC KEY-----");
    return;
  }

  add_pem(
      "-----BEGIN RSA PUBLIC KEY-----\n"
      "MIIBCgKCAQEAw66UV/20T0e5G5OJQBkz8tCyc1f+EW7XZAeYeEgp/bxmKVFp0dMj\n"
      "q2ZP1pIO+6rIcl2n6sqkkdHx7sglnKaOTP6G/GgjyQOjI95GwOZLjdXJOhiHEcG/\n"
      "ePy+DJmQQiembJE1JB3YuSoK2IqzpnNLwTtX+jhhS7KqefPvCSDVd5KPfmibe1sK\n"
      "GopI2p1+TCjyqPGq7aIqxNoFMkwctnU4rf4awyAbNKhRibB2Xmx5/0Q0M4N7VA1i\n"
      "lb+e6VuM2nCYaMRQvpcwyfzHRCAREpr7RRh8KhkTpJdHCelmaGXE8GBn6YG/V5UK\n"
      "A5W0XDpzIv02932AP/l4l7wA1Wh6PLV10QIDAQAB\n"
      "-----END RSA PUBLIC KEY-----");
}

void PublicRsaKeyShared::add_rsa(mtproto::RSA rsa) {
  auto lock = rw_mutex_.lock_write();
  auto fingerprint = rsa.get_fingerprint();
  if (get_rsa_key_unsafe(fingerprint) != nullptr) {
    return;
  }
  keys_.push_back(RsaKey{std::move(rsa), fingerprint});
}

Result<mtproto::PublicRsaKeyInterface::RsaKey> PublicRsaKeyShared::get_rsa_key(const vector<int64> &fingerprints) {
  auto lock = rw_mutex_.lock_read();
  for (auto fingerprint : fingerprints) {
    auto *rsa_key = get_rsa_key_unsafe(fingerprint);
    if (rsa_key != nullptr) {
      return RsaKey{rsa_key->rsa.clone(), fingerprint};
    }
  }
  return Status::Error(PSLICE() << "Unknown fingerprints " << format::as_array(fingerprints));
}

void PublicRsaKeyShared::drop_keys() {
  if (dc_id_.is_empty()) {
    // not CDN
    return;
  }
  auto lock = rw_mutex_.lock_write();
  LOG(INFO) << "Drop " << keys_.size() << " keys for " << dc_id_;
  keys_.clear();
  notify();
}

bool PublicRsaKeyShared::has_keys() {
  auto lock = rw_mutex_.lock_read();
  return !keys_.empty();
}

void PublicRsaKeyShared::add_listener(unique_ptr<Listener> listener) {
  if (listener->notify()) {
    auto lock = rw_mutex_.lock_write();
    listeners_.push_back(std::move(listener));
  }
}

mtproto::PublicRsaKeyInterface::RsaKey *PublicRsaKeyShared::get_rsa_key_unsafe(int64 fingerprint) {
  auto it = std::find_if(keys_.begin(), keys_.end(),
                         [fingerprint](const auto &value) { return value.fingerprint == fingerprint; });
  if (it == keys_.end()) {
    return nullptr;
  }
  return &*it;
}

void PublicRsaKeyShared::notify() {
  td::remove_if(listeners_, [&](auto &listener) { return !listener->notify(); });
}

}  // namespace td
