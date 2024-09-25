#include<vector>
#include<string>
#include<regex>

class Regex
{
public:

	static bool WStringMatch(std::wstring str, std::wstring expression);
	static std::vector<std::wstring> WStringSearch(std::wstring str, std::wstring expression, bool recursive = true);
	static std::wstring WStringReplace(std::wstring str, std::wstring expression, std::wstring replace);

	static bool StringMatch(std::string str, std::string expression);
	static std::vector<std::string> StringSearch(std::string str, std::string expression, bool recursive = true);
	static std::string StringReplace(std::string str, std::string expression, std::string replace);
};

