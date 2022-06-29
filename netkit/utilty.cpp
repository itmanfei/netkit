#include <boost/algorithm/hex.hpp>
#include <boost/uuid/detail/md5.hpp>

#include "utility.h"

namespace netkit::util {

std::string MakeMd5(const void* bytes, std::size_t bytes_size) noexcept {
  boost::uuids::detail::md5 hash;
  hash.process_bytes(bytes, bytes_size);
  boost::uuids::detail::md5::digest_type digest;
  hash.get_digest(digest);
  unsigned char raw_result[16];
  unsigned char* p = raw_result;
  for (auto chunk = 0; chunk < 4; ++chunk) {
    const unsigned char* cin =
        reinterpret_cast<const unsigned char*>(&digest[chunk]);
    for (auto byte = 0; byte < 4; ++byte) {
#if BOOST_ENDIAN_LITTLE_BYTE
      *p++ = *(cin + (3 - byte));
#else
      *p++ = *(cin + byte);
#endif
    }
  }
  std::string result;
  boost::algorithm::hex_lower(
      raw_result, raw_result + sizeof(boost::uuids::detail::md5::digest_type),
      std::back_inserter(result));
  return result;
}

}  // namespace netkit::util
