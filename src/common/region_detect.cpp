// Node-name region detection. See region_detect.hpp for the signal model.
#include "aps/region_detect.hpp"

#include <map>
#include <vector>

namespace aps::region {

namespace {

// --- UTF-8 helpers -------------------------------------------------------------
std::vector<uint32_t> decodeUtf8(std::string_view s) {
    std::vector<uint32_t> cps;
    cps.reserve(s.size());
    for (size_t i = 0; i < s.size();) {
        unsigned char c = static_cast<unsigned char>(s[i]);
        uint32_t cp = 0;
        size_t n = 0;
        if (c < 0x80) { cp = c; n = 1; }
        else if ((c & 0xE0) == 0xC0 && i + 1 < s.size()) {
            cp = (c & 0x1F) << 6 | (s[i + 1] & 0x3F); n = 2;
        } else if ((c & 0xF0) == 0xE0 && i + 2 < s.size()) {
            cp = (c & 0x0F) << 12 | (s[i + 1] & 0x3F) << 6 | (s[i + 2] & 0x3F); n = 3;
        } else if ((c & 0xF8) == 0xF0 && i + 3 < s.size()) {
            cp = (c & 0x07) << 18 | (s[i + 1] & 0x3F) << 12 | (s[i + 2] & 0x3F) << 6 |
                 (s[i + 3] & 0x3F); n = 4;
        }
        if (n == 0) { ++i; continue; }  // malformed: skip one byte
        cps.push_back(cp);
        i += n;
    }
    return cps;
}

void appendUtf8(std::string& out, uint32_t cp) {
    if (cp < 0x80) {
        out.push_back(static_cast<char>(cp));
    } else if (cp < 0x800) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp < 0x10000) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

bool isCjk(uint32_t cp) {
    return (cp >= 0x3400 && cp <= 0x4DBF) || (cp >= 0x4E00 && cp <= 0x9FFF) ||
           (cp >= 0xF900 && cp <= 0xFAFF);
}

// --- normalized views -----------------------------------------------------------
// Lowercased ASCII with every non-alnum byte turned into a space (token
// boundaries stay intact); CJK code points collected in order.
std::string normalizeAscii(std::string_view s) {
    std::string out;
    out.reserve(s.size());
    for (unsigned char c : s) {
        if (c >= 'A' && c <= 'Z') out.push_back(static_cast<char>(c - 'A' + 'a'));
        else if ((c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')) out.push_back(c);
        else out.push_back(' ');
    }
    return out;
}

std::string collapseSpaces(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    bool lastSpace = true;
    for (char c : s) {
        if (c == ' ') {
            if (!lastSpace) out.push_back(c);
            lastSpace = true;
        } else {
            out.push_back(c);
            lastSpace = false;
        }
    }
    while (!out.empty() && out.back() == ' ') out.pop_back();
    return out;
}

std::vector<std::string> tokens(const std::string& s) {
    std::vector<std::string> out;
    size_t start = 0;
    while (start < s.size()) {
        size_t end = s.find(' ', start);
        if (end == std::string::npos) end = s.size();
        if (end > start) out.push_back(s.substr(start, end - start));
        start = end + 1;
    }
    return out;
}

// --- signal accumulation ---------------------------------------------------------
struct Found {
    std::string region;
    bool conflict = false;
    void add(const std::string& r) {
        if (r.empty()) return;
        if (region.empty()) { region = r; return; }
        if (region != r) conflict = true;
    }
    std::string resolve() const { return conflict ? std::string() : region; }
};

const std::map<std::string, std::string>& iataCodes() {
    static const std::map<std::string, std::string> m = {
        {"hkg", "HK"}, {"tpe", "TW"}, {"khh", "TW"}, {"sin", "SG"},
        {"nrt", "JP"}, {"hnd", "JP"}, {"kix", "JP"}, {"oka", "JP"},
        {"lax", "US"}, {"sfo", "US"}, {"sea", "US"}, {"jfk", "US"},
        {"ord", "US"}, {"dfw", "US"}, {"mia", "US"}, {"atl", "US"},
        {"icn", "KR"}, {"pus", "KR"}, {"mfm", "MO"}, {"lhr", "UK"},
        {"fra", "DE"}, {"muc", "DE"}, {"cdg", "FR"}, {"ams", "NL"},
        {"syd", "AU"}, {"mel", "AU"}, {"yyz", "CA"}, {"yvr", "CA"},
        {"svo", "RU"}, {"dme", "RU"}, {"del", "IN"}, {"bom", "IN"},
        {"bkk", "TH"}, {"kul", "MY"},
    };
    return m;
}

// "city-name substring" -> region (priority 80). CJK + ASCII in one table:
// CJK entries are matched against the CJK-only view, ASCII against the
// collapsed ASCII view. This is DATA, kept deliberately comprehensive so
// that a new provider's naming rarely needs additions (the second airport
// only added 狮城/马来/澳洲 — world coverage is the point).
const std::vector<std::pair<std::string, std::string>>& cityNames() {
    static const std::vector<std::pair<std::string, std::string>> m = {
        // East / Southeast Asia
        {"东京", "JP"}, {"東京", "JP"}, {"大阪", "JP"}, {"京都", "JP"},
        {"埼玉", "JP"}, {"名古屋", "JP"}, {"横滨", "JP"}, {"横濱", "JP"},
        {"台北", "TW"}, {"臺北", "TW"}, {"新北", "TW"}, {"彰化", "TW"},
        {"高雄", "TW"}, {"新竹", "TW"}, {"台中", "TW"}, {"臺中", "TW"},
        {"首尔", "KR"}, {"首爾", "KR"}, {"春川", "KR"}, {"釜山", "KR"},
        {"香港", "HK"}, {"澳门", "MO"}, {"澳門", "MO"},
        {"新加坡", "SG"}, {"狮城", "SG"},
        {"曼谷", "TH"}, {"吉隆坡", "MY"}, {"雅加达", "ID"}, {"雅加達", "ID"},
        {"胡志明", "VN"}, {"河内", "VN"}, {"河內", "VN"}, {"马尼拉", "PH"},
        {"馬尼拉", "PH"}, {"金边", "KH"}, {"金邊", "KH"}, {"仰光", "MM"},
        {"孟买", "IN"}, {"新德里", "IN"}, {"德里", "IN"}, {"孟買", "IN"},
        // Middle East / Central Asia
        {"迪拜", "AE"}, {"迪拜", "AE"}, {"阿布扎比", "AE"}, {"多哈", "QA"},
        {"利雅得", "SA"}, {"伊斯坦布尔", "TR"}, {"伊斯坦堡", "TR"},
        {"安卡拉", "TR"}, {"特拉维夫", "IL"}, {"阿拉木图", "KZ"},
        // Europe
        {"伦敦", "UK"}, {"曼彻斯特", "UK"}, {"法兰克福", "DE"}, {"柏林", "DE"},
        {"慕尼黑", "DE"}, {"巴黎", "FR"}, {"阿姆斯特丹", "NL"}, {"马德里", "ES"},
        {"馬德里", "ES"}, {"巴塞罗那", "ES"}, {"巴塞羅那", "ES"}, {"米兰", "IT"},
        {"米蘭", "IT"}, {"罗马", "IT"}, {"羅馬", "IT"}, {"苏黎世", "CH"},
        {"蘇黎世", "CH"}, {"日内瓦", "CH"}, {"日內瓦", "CH"}, {"斯德哥尔摩", "SE"},
        {"斯德哥爾摩", "SE"}, {"华沙", "PL"}, {"華沙", "PL"}, {"布拉格", "CZ"},
        {"维也纳", "AT"}, {"維也納", "AT"}, {"布达佩斯", "HU"}, {"布達佩斯", "HU"},
        {"都柏林", "IE"}, {"赫尔辛基", "FI"}, {"赫爾辛基", "FI"}, {"奥斯陆", "NO"},
        {"奧斯陸", "NO"}, {"哥本哈根", "DK"}, {"布鲁塞尔", "BE"}, {"布魯塞爾", "BE"},
        {"里斯本", "PT"}, {"雅典", "GR"}, {"索菲亚", "BG"}, {"布加勒斯特", "RO"},
        {"基辅", "UA"}, {"基輔", "UA"}, {"莫斯科", "RU"}, {"圣彼得堡", "RU"},
        {"聖彼得堡", "RU"}, {"新西伯利亚", "RU"}, {"海参崴", "RU"}, {"海參崴", "RU"},
        // Americas
        {"洛杉矶", "US"}, {"硅谷", "US"}, {"西雅图", "US"}, {"芝加哥", "US"},
        {"纽约", "US"}, {"纽约", "US"}, {"波特兰", "US"}, {"达拉斯", "US"},
        {"達拉斯", "US"}, {"迈阿密", "US"}, {"邁阿密", "US"}, {"圣何塞", "US"},
        {"聖何塞", "US"}, {"费城", "US"}, {"費城", "US"}, {"亚特兰大", "US"},
        {"亞特蘭大", "US"}, {"凤凰城", "US"}, {"鳳凰城", "US"}, {"丹佛", "US"},
        {"拉斯维加斯", "US"}, {"拉斯維加斯", "US"}, {"多伦多", "CA"}, {"多倫多", "CA"},
        {"温哥华", "CA"}, {"溫哥華", "CA"}, {"蒙特利尔", "CA"}, {"蒙特利爾", "CA"},
        {"墨西哥城", "MX"}, {"圣保罗", "BR"}, {"聖保羅", "BR"}, {"里约", "BR"},
        {"里約", "BR"}, {"布宜诺斯艾利斯", "AR"}, {"布宜諾斯艾利斯", "AR"},
        {"圣地亚哥", "CL"}, {"聖地亞哥", "CL"}, {"波哥大", "CO"}, {"利马", "PE"},
        // Africa
        {"开罗", "EG"}, {"開羅", "EG"}, {"约翰内斯堡", "ZA"}, {"約翰內斯堡", "ZA"},
        {"开普敦", "ZA"}, {"開普敦", "ZA"}, {"内罗毕", "KE"}, {"內羅畢", "KE"},
        {"拉各斯", "NG"}, {"卡萨布兰卡", "MA"}, {"卡薩布蘭卡", "MA"},
        // Oceania
        {"悉尼", "AU"}, {"悉尼", "AU"}, {"墨尔本", "AU"}, {"墨爾本", "AU"},
        {"布里斯班", "AU"}, {"珀斯", "AU"}, {"奥克兰", "NZ"}, {"奧克蘭", "NZ"},
        {"惠灵顿", "NZ"}, {"惠靈頓", "NZ"},
        // English city names (providers that name nodes in English)
        {"tokyo", "JP"}, {"osaka", "JP"}, {"nagoya", "JP"}, {"yokohama", "JP"},
        {"taipei", "TW"}, {"kaohsiung", "TW"}, {"seoul", "KR"}, {"busan", "KR"},
        {"hong kong", "HK"}, {"macau", "MO"}, {"macao", "MO"},
        {"singapore", "SG"}, {"bangkok", "TH"}, {"kuala lumpur", "MY"},
        {"jakarta", "ID"}, {"ho chi minh", "VN"}, {"hanoi", "VN"},
        {"manila", "PH"}, {"mumbai", "IN"}, {"delhi", "IN"}, {"dubai", "AE"},
        {"doha", "QA"}, {"riyadh", "SA"}, {"istanbul", "TR"},
        {"london", "UK"}, {"manchester", "UK"}, {"frankfurt", "DE"},
        {"berlin", "DE"}, {"munich", "DE"}, {"paris", "FR"},
        {"amsterdam", "NL"}, {"madrid", "ES"}, {"barcelona", "ES"},
        {"milan", "IT"}, {"rome", "IT"}, {"zurich", "CH"}, {"geneva", "CH"},
        {"stockholm", "SE"}, {"warsaw", "PL"}, {"prague", "CZ"},
        {"vienna", "AT"}, {"budapest", "HU"}, {"dublin", "IE"},
        {"helsinki", "FI"}, {"oslo", "NO"}, {"copenhagen", "DK"},
        {"brussels", "BE"}, {"lisbon", "PT"}, {"athens", "GR"},
        {"bucharest", "RO"}, {"kiev", "UA"}, {"moscow", "RU"},
        {"los angeles", "US"}, {"silicon valley", "US"}, {"seattle", "US"},
        {"chicago", "US"}, {"new york", "US"}, {"portland", "US"},
        {"dallas", "US"}, {"miami", "US"}, {"san jose", "US"},
        {"philadelphia", "US"}, {"atlanta", "US"}, {"denver", "US"},
        {"las vegas", "US"}, {"toronto", "CA"}, {"vancouver", "CA"},
        {"montreal", "CA"}, {"mexico city", "MX"}, {"sao paulo", "BR"},
        {"buenos aires", "AR"}, {"santiago", "CL"}, {"bogota", "CO"},
        {"lima", "PE"}, {"cairo", "EG"}, {"johannesburg", "ZA"},
        {"capetown", "ZA"}, {"nairobi", "KE"}, {"lagos", "NG"},
        {"casablanca", "MA"}, {"sydney", "AU"}, {"melbourne", "AU"},
        {"brisbane", "AU"}, {"perth", "AU"}, {"auckland", "NZ"},
        {"wellington", "NZ"},
    };
    return m;
}

// Country names (priority 75).
const std::vector<std::pair<std::string, std::string>>& countryNames() {
    static const std::vector<std::pair<std::string, std::string>> m = {
        {"香港", "HK"}, {"台湾", "TW"}, {"臺灣", "TW"}, {"日本", "JP"},
        {"新加坡", "SG"}, {"美国", "US"}, {"美國", "US"}, {"韩国", "KR"},
        {"韓國", "KR"}, {"澳门", "MO"}, {"澳門", "MO"}, {"英国", "UK"},
        {"英國", "UK"}, {"德国", "DE"}, {"德國", "DE"}, {"加拿大", "CA"},
        {"澳大利亚", "AU"}, {"澳大利亞", "AU"}, {"澳洲", "AU"},
        {"马来西亚", "MY"}, {"馬來西亞", "MY"}, {"马来", "MY"},
        {"法国", "FR"}, {"法國", "FR"},
        {"俄罗斯", "RU"}, {"俄羅斯", "RU"}, {"印度", "IN"}, {"泰国", "TH"},
        {"泰國", "TH"}, {"马来西亚", "MY"}, {"馬來西亞", "MY"},
        {"越南", "VN"}, {"印度尼西亚", "ID"}, {"印尼", "ID"},
        {"菲律宾", "PH"}, {"菲律賓", "PH"}, {"柬埔寨", "KH"},
        {"缅甸", "MM"}, {"緬甸", "MM"}, {"土耳其", "TR"}, {"以色列", "IL"},
        {"哈萨克斯坦", "KZ"}, {"哈薩克斯坦", "KZ"},
        {"荷兰", "NL"}, {"荷蘭", "NL"}, {"西班牙", "ES"}, {"意大利", "IT"},
        {"瑞士", "CH"}, {"瑞典", "SE"}, {"波兰", "PL"}, {"波蘭", "PL"},
        {"墨西哥", "MX"}, {"阿根廷", "AR"}, {"巴西", "BR"}, {"南非", "ZA"},
        {"埃及", "EG"}, {"新西兰", "NZ"}, {"新西蘭", "NZ"},
        {"阿联酋", "AE"}, {"阿聯酋", "AE"}, {"沙特", "SA"}, {"卡塔尔", "QA"},
        {"卡塔爾", "QA"},
        {"hong kong", "HK"}, {"hongkong", "HK"}, {"taiwan", "TW"},
        {"japan", "JP"}, {"singapore", "SG"}, {"united states", "US"},
        {"usa", "US"}, {"america", "US"}, {"korea", "KR"}, {"germany", "DE"},
        {"united kingdom", "UK"}, {"canada", "CA"}, {"australia", "AU"},
        {"france", "FR"}, {"russia", "RU"}, {"india", "IN"},
        {"thailand", "TH"}, {"malaysia", "MY"}, {"vietnam", "VN"},
        {"indonesia", "ID"}, {"philippines", "PH"}, {"cambodia", "KH"},
        {"myanmar", "MM"}, {"turkey", "TR"}, {"israel", "IL"},
        {"kazakhstan", "KZ"}, {"netherlands", "NL"}, {"spain", "ES"},
        {"italy", "IT"}, {"switzerland", "CH"}, {"sweden", "SE"},
        {"poland", "PL"}, {"mexico", "MX"}, {"argentina", "AR"},
        {"brazil", "BR"}, {"south africa", "ZA"}, {"egypt", "EG"},
        {"new zealand", "NZ"}, {"uae", "AE"}, {"saudi arabia", "SA"},
        {"qatar", "QA"},
    };
    return m;
}

const std::map<std::string, std::string>& isoCodes() {
    static const std::map<std::string, std::string> m = {
        {"hk", "HK"}, {"tw", "TW"}, {"sg", "SG"}, {"jp", "JP"}, {"us", "US"},
        {"kr", "KR"}, {"mo", "MO"}, {"uk", "UK"}, {"gb", "UK"}, {"de", "DE"},
        {"au", "AU"}, {"ca", "CA"}, {"fr", "FR"}, {"ru", "RU"}, {"in", "IN"},
        {"th", "TH"}, {"my", "MY"}, {"nl", "NL"}, {"es", "ES"}, {"it", "IT"},
        {"se", "SE"}, {"ch", "CH"}, {"kz", "KZ"}, {"tr", "TR"}, {"br", "BR"},
        {"za", "ZA"},
    };
    return m;
}

const std::map<std::string, std::string>& singleCjk() {
    static const std::map<std::string, std::string> m = {
        {"港", "HK"}, {"台", "TW"}, {"日", "JP"}, {"美", "US"}, {"韩", "KR"},
        {"坡", "SG"},
    };
    return m;
}

// Multi-keyword scan: first hit per table entry; same-priority distinct
// regions conflict (conservative).
void scanTable(const std::vector<std::pair<std::string, std::string>>& table,
               const std::string& hay, Found& f) {
    for (const auto& [word, region] : table) {
        if (hay.find(word) != std::string::npos) f.add(region);
    }
}

}  // namespace

std::string detectNodeRegion(std::string_view nodeName) {
    if (nodeName.empty()) return "";
    const std::vector<uint32_t> cps = decodeUtf8(nodeName);

    // 1) Emoji flag pairs (priority 100): consecutive Regional Indicator
    //    symbols -> two-letter ISO code. Decisive; conflicts -> unknown.
    Found flags;
    for (size_t i = 0; i + 1 < cps.size(); ++i) {
        bool a = cps[i] >= 0x1F1E6 && cps[i] <= 0x1F1FF;
        bool b = cps[i + 1] >= 0x1F1E6 && cps[i + 1] <= 0x1F1FF;
        if (a && b) {
            std::string code;
            code.push_back(static_cast<char>('A' + cps[i] - 0x1F1E6));
            code.push_back(static_cast<char>('A' + cps[i + 1] - 0x1F1E6));
            flags.add(code);
            ++i;
        }
    }
    if (!flags.region.empty() || flags.conflict) return flags.resolve();

    const std::string ascii = collapseSpaces(normalizeAscii(nodeName));
    std::string cjk;
    for (uint32_t cp : cps) {
        if (isCjk(cp)) appendUtf8(cjk, cp);
    }

    // 2) IATA airport codes (90): whole tokens only.
    Found iata;
    for (const auto& t : tokens(ascii)) {
        auto it = iataCodes().find(t);
        if (it != iataCodes().end()) iata.add(it->second);
    }
    if (!iata.region.empty() || iata.conflict) return iata.resolve();

    // 3) City names (80), 4) country names (75): CJK against the CJK view,
    //    ASCII against the collapsed ASCII view.
    Found city;
    scanTable(cityNames(), cjk, city);
    scanTable(cityNames(), ascii, city);
    if (!city.region.empty() || city.conflict) return city.resolve();

    Found country;
    scanTable(countryNames(), cjk, country);
    scanTable(countryNames(), ascii, country);
    if (!country.region.empty() || country.conflict) return country.resolve();

    // 5) ISO 2-letter tokens + (English names already handled above at 75 —
    //    the remaining English entries here are covered by country/city).
    //    Whole-token ISO codes (70).
    Found iso;
    for (const auto& t : tokens(ascii)) {
        auto it = isoCodes().find(t);
        if (it != isoCodes().end()) iso.add(it->second);
    }
    if (!iso.region.empty() || iso.conflict) return iso.resolve();

    // 6) Single Chinese characters (50): weakest, but very common in
    //    airport naming ("港/台/日/美/韩/坡"). "新" is deliberately absent
    //    (新加坡 vs 新西兰 ambiguity).
    Found single;
    for (uint32_t cp : cps) {
        if (!isCjk(cp)) continue;
        std::string ch;
        appendUtf8(ch, cp);
        auto it = singleCjk().find(ch);
        if (it != singleCjk().end()) single.add(it->second);
    }
    return single.resolve();
}

bool matches(std::string_view detected, std::string_view wanted) {
    if (wanted.empty()) return true;   // 不限
    return detected == wanted;
}

bool matchesAny(std::string_view detected,
                const std::vector<std::string>& wanted) {
    if (wanted.empty()) return true;   // 不限
    for (const auto& w : wanted) {
        if (detected == w) return true;
    }
    return false;
}

}  // namespace aps::region
