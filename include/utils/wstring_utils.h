#ifndef WSTRING_UTILS_H
#define WSTRING_UTILS_H

#include <string>
#include <algorithm>
#include <cwctype> // for towlower, towupper

namespace WStringUtils {

    // Trim whitespace from start and end
    inline std::wstring trim(const std::wstring& str) {
        std::wstring result = str;

        // trim start
        result.erase(result.begin(), std::find_if(result.begin(), result.end(),
            [](wchar_t ch) { return !iswspace(ch); }));

        // trim end
        result.erase(std::find_if(result.rbegin(), result.rend(),
            [](wchar_t ch) { return !iswspace(ch); }).base(), result.end());

        return result;
    }

    // Convert to lowercase
    inline std::wstring toLower(const std::wstring& str) {
        std::wstring result = str;
        std::transform(result.begin(), result.end(), result.begin(),
            [](wchar_t c) { return towlower(c); }); // remove std::
        return result;
    }

    // Convert to uppercase
    inline std::wstring toUpper(const std::wstring& str) {
        std::wstring result = str;
        std::transform(result.begin(), result.end(), result.begin(),
            [](wchar_t c) { return towupper(c); }); // remove std::
        return result;
    }

    // Check if a wstring contains a substring
    inline bool contains(const std::wstring& str, const std::wstring& substring) {
        return str.find(substring) != std::wstring::npos;
    }

} // namespace WStringUtils

#endif // WSTRING_UTILS_H
