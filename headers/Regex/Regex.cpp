#include "Regex.h"

bool Regex::WStringMatch(std::wstring str, std::wstring expression)
{
    std::wsmatch wm;
    std::wregex str_expr(expression);
    std::regex_match(str, wm, str_expr);
    return (bool)wm.size();
}

std::vector<std::wstring> Regex::WStringSearch(std::wstring str, std::wstring expression, bool recursive)
{
    std::wsmatch matched;
    std::wregex str_expr(expression);
    std::vector<std::wstring>  buffer;

    if (!recursive)
    {
        std::regex_search(str, matched, str_expr);
        buffer.push_back(matched.str());
        goto ret;
    }

    if (recursive)
    {
        while (std::regex_search(str, matched, str_expr))
        {
            if (!matched.str().length())
                break;

            buffer.push_back(matched.str());
            str = matched.suffix();
        }
        goto ret;
    }

ret:
    return buffer;
}

std::wstring Regex::WStringReplace(std::wstring str, std::wstring expression, std::wstring replace)
{
    return std::regex_replace(str, std::wregex(expression), replace);
}

bool Regex::StringMatch(std::string str, std::string expression)
{
    return (bool)std::regex_match(str, std::regex(expression));
}

std::vector<std::string>  Regex::StringSearch(std::string str, std::string expression, bool recursive)
{
    std::smatch matched;
    std::regex str_expr(expression);
    std::vector<std::string>  buffer;
    if (recursive)
    {

        while (regex_search(str, matched, str_expr))
        {
            if (!matched.str().length())
                break;
            buffer.push_back(matched.str());
            str = matched.suffix();
        }

    }
    else if (!recursive)
    {
        regex_search(str, matched, str_expr);
        buffer.push_back(matched.str());
    }
    return buffer;
}

std::string Regex::StringReplace(std::string str, std::string expression, std::string replace)
{
    return std::regex_replace(str, std::regex(expression), replace);
}