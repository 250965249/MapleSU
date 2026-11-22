#include "kernel_version_parser.h"
#include <sstream>
#include <cstring>
#include <charconv>
#include <stdexcept>

#ifndef MIN
#define MIN(x, y)(x < y) ? (x) : (y)
#endif // !MIN

KernelVersionParser::KernelVersionParser(const std::vector<char>& file_buf) : m_file_buf(file_buf) {
  m_ver = find_kernel_versions();
  m_tag = find_kernel_tag();
}

KernelVersionParser::~KernelVersionParser() {}

std::string KernelVersionParser::get_kernel_version() const {
	return m_ver;
}

std::string KernelVersionParser::get_kernel_tag() const {
	return m_tag;
}

bool KernelVersionParser::is_kernel_version_less(const std::string& ver) const {
	if (!m_ver.empty()) {
		return is_version_less(m_ver, ver);
	}
	return false;
}

// Helper function to extract and print the version number starting from the given index
std::string KernelVersionParser::extract_version(const std::vector<char>& buffer, size_t start_index) const {
	std::string version;
	// Extract until we hit a non-version character or end of buffer
	while (start_index < buffer.size() && ((buffer[start_index] >= '0' && buffer[start_index] <= '9') || buffer[start_index] == '.')) {
		version.push_back(buffer[start_index]);
		++start_index;
	}
	return version;
}

// Function to search for Linux version patterns using memcmp
std::string KernelVersionParser::find_kernel_versions() const {
	const char* prefix = "Linux version ";
	const size_t prefix_len = strlen(prefix);

	std::string result;
	for (size_t i = 0; i + prefix_len < m_file_buf.size(); ++i) {
		if (memcmp(m_file_buf.data() + i, prefix, prefix_len) == 0) {
			auto candidate = extract_version(m_file_buf, i + prefix_len);
			try { parse_version(candidate); }
			catch (const std::invalid_argument&) { continue; }
			if (!result.empty() && result != candidate) return {};
			result = candidate;
		}
	}
	return result;
}

// Function to extract the kernel tag (the full "Linux version ..." text ending at '\0').
// Returns the longest tag found across the buffer, or empty if none is found.
std::string KernelVersionParser::find_kernel_tag() const {
	const char* prefix = "Linux version ";
	const size_t prefix_len = strlen(prefix);
	std::string longest;
	if (m_ver.empty()) return longest;

	for (size_t i = 0; i + prefix_len < m_file_buf.size(); ++i) {
		if (memcmp(m_file_buf.data() + i, prefix, prefix_len) == 0 && extract_version(m_file_buf, i + prefix_len) == m_ver) {
			// Find the end of the tag: continue forward until a '\0' terminator.
			size_t end = i;
			while (end < m_file_buf.size() && m_file_buf[end] != '\0') {
				++end;
			}
			const size_t len = end - i;
			if (len > longest.size()) {
				longest.assign(m_file_buf.data() + i, len);
			}
		}
	}
	return longest;
}


// Helper function to split the version string and convert to integers
std::vector<int> KernelVersionParser::parse_version(const std::string& version) const {
	std::vector<int> parts;
	if (version.empty() || version.back() == '.') throw std::invalid_argument("KERNEL_VERSION_INVALID");
	size_t begin = 0;
	while (begin < version.size()) {
		const size_t dot = version.find('.', begin);
		const size_t end = dot == std::string::npos ? version.size() : dot;
		int value = 0;
		const auto parsed = std::from_chars(version.data() + begin, version.data() + end, value);
		if (begin == end || version[begin] < '0' || version[begin] > '9' ||
			parsed.ec != std::errc{} || parsed.ptr != version.data() + end || parts.size() == 3)
			throw std::invalid_argument("KERNEL_VERSION_INVALID");
		parts.push_back(value);
		begin = end + 1;
	}
	// Ensure we always have at least three parts (fill missing parts with zero)
	while (parts.size() < 3) {
		parts.push_back(0);
	}

	return parts;
}

// Function to compare two version numbers
bool KernelVersionParser::is_version_less(const std::string& v1, const std::string& v2) const {
	auto parts1 = parse_version(v1);
	auto parts2 = parse_version(v2);

	// Compare major, minor, and patch versions
	for (int i = 0; i < 3; ++i) {
		if (parts1[i] < parts2[i]) return true;  // If version 1 is less than version 2, return true
		if (parts1[i] > parts2[i]) return false; // If version 1 is greater than version 2, return false
	}

	// If all parts are equal, return false (i.e., v1 is not less than v2)
	return false;  // If versions are equal, return false (strictly less)
}
