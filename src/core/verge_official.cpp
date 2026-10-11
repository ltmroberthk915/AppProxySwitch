#include "aps/verge_official.hpp"
#include "aps/string_util.hpp"
#include "aps/json.hpp"
#include "aps/clash_pipe.hpp"
#include "aps/clash_api.hpp"
#include "aps/kernel_config.hpp"
#include <windows.h>
#include <ole2.h>
#include <shlobj.h>
#include <uiautomation.h>
#include <wrl/client.h>
#include <winhttp.h>
#include <filesystem>
#include <sstream>
#include <algorithm>
#include <ctime>
#include <stdexcept>
#include <cmath>
#include <charconv>
#include <cwctype>

namespace aps {
namespace {
using Microsoft::WRL::ComPtr;
std::string scalar(std::string v) {
    v=std::string(trim(v));
    if(v=="null" || v=="~") return {};
    if(!v.empty() && v.front()=='"') {
        json::Value x; if(!json::Value::parse(v,x,nullptr) || !x.isString()) return {};
        return x.asString();
    }
    if(v.size()>=2 && v.front()=='\'' && v.back()=='\'') {
        v=v.substr(1,v.size()-2);
        for(size_t p=0;(p=v.find("''",p))!=std::string::npos;++p) v.erase(p,1);
    }
    return v;
}
std::string readFile(const std::filesystem::path& path, uint64_t offset=0,
                     uint64_t limit=8*1024*1024) {
    HANDLE h=CreateFileW(path.c_str(),GENERIC_READ,FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
                         nullptr,OPEN_EXISTING,FILE_ATTRIBUTE_NORMAL,nullptr);
    if(h==INVALID_HANDLE_VALUE) throw std::runtime_error("无法读取 Verge 文件");
    LARGE_INTEGER n{}; GetFileSizeEx(h,&n);
    if(n.QuadPart<0 || offset>static_cast<uint64_t>(n.QuadPart) || n.QuadPart-offset>limit) {
        CloseHandle(h); throw std::runtime_error("Verge 文件变动过大或日志已轮换，请在客户端核对");
    }
    LARGE_INTEGER pos{}; pos.QuadPart=static_cast<LONGLONG>(offset); SetFilePointerEx(h,pos,nullptr,FILE_BEGIN);
    std::string out(static_cast<size_t>(n.QuadPart-offset),'\0'); DWORD got=0;
    BOOL ok=ReadFile(h,out.data(),static_cast<DWORD>(out.size()),&got,nullptr); CloseHandle(h);
    if(!ok) throw std::runtime_error("读取 Verge 文件失败");
    out.resize(got); return out;
}
std::wstring imagePath(DWORD pid) {
    HANDLE h=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid);
    if(!h) return {};
    wchar_t b[32768]; DWORD n=32768; BOOL ok=QueryFullProcessImageNameW(h,0,b,&n); CloseHandle(h);
    return ok ? std::wstring(b,n):std::wstring();
}
bool sameUser(DWORD pid) {
    HANDLE p=OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,pid), a=nullptr,b=nullptr;
    bool ok=false;
    if(p && OpenProcessToken(p,TOKEN_QUERY,&a) && OpenProcessToken(GetCurrentProcess(),TOKEN_QUERY,&b)) {
        DWORD na=0,nb=0; GetTokenInformation(a,TokenUser,nullptr,0,&na); GetTokenInformation(b,TokenUser,nullptr,0,&nb);
        std::vector<char> va(na),vb(nb);
        if(GetTokenInformation(a,TokenUser,va.data(),na,&na) && GetTokenInformation(b,TokenUser,vb.data(),nb,&nb))
            ok=EqualSid(reinterpret_cast<TOKEN_USER*>(va.data())->User.Sid,reinterpret_cast<TOKEN_USER*>(vb.data())->User.Sid)!=FALSE;
    }
    if(a)CloseHandle(a); if(b)CloseHandle(b); if(p)CloseHandle(p); return ok;
}
bool live(HANDLE h) { DWORD code=0; return GetExitCodeProcess(h,&code) && code==STILL_ACTIVE; }
struct Handle { HANDLE h=nullptr; ~Handle(){if(h)CloseHandle(h);} };
struct ComScope { HRESULT hr=CoInitializeEx(nullptr,COINIT_MULTITHREADED); ~ComScope(){if(SUCCEEDED(hr))CoUninitialize();} };
std::wstring name(IUIAutomationElement* e) {
    BSTR s=nullptr; if(FAILED(e->get_CurrentName(&s))) return {};
    std::wstring v=s?s:L""; SysFreeString(s); return v;
}
ComPtr<IUIAutomationElementArray> find(IUIAutomation* ui,IUIAutomationElement* root,
                                      PROPERTYID prop,const VARIANT& value) {
    ComPtr<IUIAutomationCondition> c; ComPtr<IUIAutomationElementArray> a;
    if(FAILED(ui->CreatePropertyCondition(prop,value,&c)) || FAILED(root->FindAll(TreeScope_Descendants,c.Get(),&a)))
        throw std::runtime_error("无法读取官方 Verge 窗口");
    return a;
}
ComPtr<IUIAutomationElementArray> named(IUIAutomation* ui,IUIAutomationElement* root,const std::wstring& s) {
    VARIANT v{}; v.vt=VT_BSTR; v.bstrVal=SysAllocString(s.c_str());
    auto a=find(ui,root,UIA_NamePropertyId,v); VariantClear(&v); return a;
}
ComPtr<IUIAutomationElement> uniqueButton(IUIAutomation* ui,IUIAutomationElement* root,const std::vector<std::wstring>& names) {
    ComPtr<IUIAutomationElement> result; int count=0;
    std::vector<std::string> actions; for(const auto& s:names)actions.push_back(wideToUtf8(s));
    VARIANT type{};type.vt=VT_I4;type.lVal=UIA_ButtonControlTypeId;
    auto buttons=find(ui,root,UIA_ControlTypePropertyId,type);int total=0;buttons->get_Length(&total);
    for(int i=0;i<total;++i) {
        ComPtr<IUIAutomationElement> e;buttons->GetElement(i,&e);
        bool matches=vergeActionLabelMatches(wideToUtf8(name(e.Get())),actions);
        // Tooltip/WebView changes can move the action to another accessible
        // property. Count each physical button once, even with several labels.
        for(auto prop:{UIA_HelpTextPropertyId,UIA_FullDescriptionPropertyId}) {
            if(matches)break;
            VARIANT value{};
            if(SUCCEEDED(e->GetCurrentPropertyValue(prop,&value)) && value.vt==VT_BSTR && value.bstrVal)
                matches=vergeActionLabelMatches(wideToUtf8(value.bstrVal),actions);
            VariantClear(&value);
        }
        if(matches){result=e;++count;}
    }
    if(count!=1) return {}; return result;
}
void invoke(IUIAutomationElement* e) {
    BOOL enabled=FALSE; if(!e || FAILED(e->get_CurrentIsEnabled(&enabled)) || !enabled)
        throw std::runtime_error("Verge 按钮不可用或正在更新，请稍后核对");
    ComPtr<IUIAutomationInvokePattern> p;
    if(FAILED(e->GetCurrentPatternAs(UIA_InvokePatternId,IID_PPV_ARGS(&p))))
        throw std::runtime_error("官方按钮未提供 Invoke 接口；未使用坐标点击兜底");
    // Never retry Invoke: even a failed COM reply may follow a delivered click.
    if(FAILED(p->Invoke())) throw std::runtime_error("按钮调用结果未确认；请在 Verge 核对，不会自动重试");
}
std::wstring dateOf(const std::string& seconds) {
    try { auto t=static_cast<__time64_t>(std::stoll(seconds)); tm x{}; if(_localtime64_s(&x,&t)!=0)return {};
        wchar_t b[32]; wcsftime(b,32,L"%Y-%m-%d",&x); return b; } catch(...) { return {}; }
}
}

bool vergeActionLabelMatches(const std::string& label,const std::vector<std::string>& actions) {
    auto normalize=[](const std::string& text) {
        std::wstring out;
        for(const auto c:utf8ToWide(text))if(!iswspace(c) && c!=0x200B)out+=static_cast<wchar_t>(towlower(c));
        while(!out.empty() && (out.back()==L'.' || out.back()==L'…'))out.pop_back();
        return out;
    };
    const auto value=normalize(label);
    return !value.empty() && std::any_of(actions.begin(),actions.end(),[&](const auto& action){return value==normalize(action);});
}

bool parseVergeInstanceRecord(const std::string& text, VergeInstanceRecord& record) {
    record={};
    json::Value value;
    if(text.size()>4096 || !json::Value::parse(text,value,nullptr) || !value.isObject())return false;
    const auto* port=value.find("port"); const auto* token=value.find("token");
    if(!port || !port->isNumber() || !token || !token->isString())return false;
    const auto number=port->asNumber();
    if(!std::isfinite(number) || number<1 || number>65535 || std::floor(number)!=number)return false;
    const auto& credential=token->asString();
    // Bounded visible ASCII, not a version-specific length/hex assumption.
    // Whitespace and controls must never become additional HTTP headers.
    if(credential.empty() || credential.size()>512 ||
       !std::all_of(credential.begin(),credential.end(),[](unsigned char c){return c>=33 && c<=126;}))return false;
    record.port=static_cast<uint16_t>(number); record.token=credential; return true;
}

std::string vergeControllerOwnerKey(const std::string& pipe) {
    const auto folded=toLowerAscii(pipe);
    return folded.starts_with("\\\\.\\pipe\\verge-mihomo-")
        ?controllerPipeInstanceKey(pipe):std::string();
}

bool vergeControllerMatchesRuntime(const DiscoveredKernel& kernel,const std::string& runtimeYaml) {
    const auto config=parseKernelLaunchConfig({},runtimeYaml);
    if(!kernel.socksPort || (kernel.socksPort!=config.mixedPort && kernel.socksPort!=config.socksPort) ||
       !localControllerPipe(kernel.apiPipe) || !localControllerPipe(config.pipe))return false;
    if(toLowerAscii(kernel.apiPipe)==toLowerAscii(config.pipe))return true;
    const auto owner=controllerPipeInstanceKey(kernel.apiPipe);
    return !owner.empty() && owner==controllerPipeInstanceKey(config.pipe);
}

bool resolveOfficialVergeClient(const DiscoveredKernel& kernel,uint32_t& clientPid,
                                std::filesystem::path& dataDir,std::string& error) {
    clientPid=0;dataDir.clear();error.clear();
    auto fail=[&](const char* message){clientPid=0;dataDir.clear();error=message;return false;};
    if(!kernel.pid || !localControllerPipe(kernel.apiPipe))
        return fail("未取得所选 Verge 的控制器身份；未执行更新");
    const auto coreName=processNameOf(kernel.pid);
    if(coreName.empty() || (!kernel.procName.empty() && !equalsIgnoreCase(coreName,kernel.procName)))
        return fail("所选 Verge 内核已退出或身份已变化；未执行更新");
    // Pin the server PID and validate its JSON identity before trusting the
    // per-user owner key. Names and matching port numbers alone are hints.
    std::string probeError;
    if(!ClashApiClient("127.0.0.1",0,kernel.apiSecret,kernel.apiPipe,kernel.pid).probe(&probeError,1500))
        return fail("所选 Verge 控制器身份验证失败；未执行更新");
    for(auto pid:findProcessIdsByName({"clash-verge"})) {
        const auto path=imagePath(pid);
        if(path.empty() || !equalsIgnoreCase(wideToUtf8(std::filesystem::path(path).filename().wstring()),"clash-verge.exe") ||
           !sameUser(pid))continue;
        const auto installDir=std::filesystem::path(path).parent_path();
        std::filesystem::path dir;
        try {
            if(std::filesystem::exists(installDir/L".config"/L"PORTABLE"))
                dir=installDir/L".config"/L"io.github.clash-verge-rev.clash-verge-rev";
            else {
                PWSTR roaming=nullptr;
                if(FAILED(SHGetKnownFolderPath(FOLDERID_RoamingAppData,0,nullptr,&roaming)))continue;
                dir=std::filesystem::path(roaming)/L"io.github.clash-verge-rev.clash-verge-rev";
                CoTaskMemFree(roaming);
            }
            if(!vergeControllerMatchesRuntime(kernel,readFile(dir/L"clash-verge.yaml",0,4*1024*1024)))continue;
            if(!kernel.configDir.empty()) {
                const auto discoveredDir=std::filesystem::path(utf8ToWide(kernel.configDir));
                if(std::filesystem::exists(discoveredDir/L"profiles.yaml") &&
                   toLowerAsciiW(std::filesystem::weakly_canonical(discoveredDir).wstring())!=
                   toLowerAsciiW(std::filesystem::weakly_canonical(dir).wstring()))continue;
            }
        } catch(...) {continue;}
        if(clientPid)return fail("存在多个对应 Verge 客户端，请保留唯一目标窗口；未执行更新");
        clientPid=pid;dataDir=std::move(dir);
    }
    return clientPid!=0 || fail("未找到与所选控制器匹配的同用户官方 Verge 客户端；未执行更新");
}

bool requestOfficialVergeWindow(uint32_t clientPid,const std::filesystem::path& dataDir,
                                std::string* diagnostic) {
    auto fail=[&](const std::string& code){if(diagnostic)*diagnostic=code;return false;};
    if(diagnostic)diagnostic->clear();
    if(!clientPid)return fail("window.identity");
    Handle client{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,clientPid)};
    if(!client.h || !live(client.h) || !sameUser(clientPid))return fail("window.identity");
    auto ports=listeningPortsOf(clientPid);
    std::sort(ports.begin(),ports.end()); ports.erase(std::unique(ports.begin(),ports.end()),ports.end());
    VergeInstanceRecord record;
    if(!dataDir.empty()) {
        try {
            const auto path=dataDir/L"singleton-instance.json";
            const auto attr=GetFileAttributesW(path.c_str());
            if(attr==INVALID_FILE_ATTRIBUTES) {
                const auto error=GetLastError();
                if(error!=ERROR_FILE_NOT_FOUND && error!=ERROR_PATH_NOT_FOUND)return fail("window.record_read");
            } else {
                if((attr&(FILE_ATTRIBUTE_DIRECTORY|FILE_ATTRIBUTE_REPARSE_POINT)) ||
                   !parseVergeInstanceRecord(readFile(path,0,4096),record))return fail("window.record_invalid");
            }
        } catch(...) {return fail("window.record_read");}
    }
    if(record.port) {
        if(std::find(ports.begin(),ports.end(),record.port)==ports.end())return fail("window.record_owner");
    } else {
        if(ports.empty())return fail("window.no_listener");
        if(ports.size()!=1)return fail("window.ambiguous_listener");
        record.port=ports.front();
    }
    struct Http { HINTERNET h=nullptr; ~Http(){if(h)WinHttpCloseHandle(h);} };
    Http session{WinHttpOpen(L"APS-Verge-Window",WINHTTP_ACCESS_TYPE_NO_PROXY,
                            WINHTTP_NO_PROXY_NAME,WINHTTP_NO_PROXY_BYPASS,0)};
    auto httpFail=[&]{return fail("window.transport_"+std::to_string(GetLastError()));};
    if(!session.h)return httpFail();
    WinHttpSetTimeouts(session.h,1500,1500,1500,1500);
    Http connection{WinHttpConnect(session.h,L"127.0.0.1",record.port,0)};
    if(!connection.h)return httpFail();
    Http request{WinHttpOpenRequest(connection.h,L"GET",L"/commands/visible",nullptr,
                                   WINHTTP_NO_REFERER,WINHTTP_DEFAULT_ACCEPT_TYPES,0)};
    if(!request.h)return httpFail();
    DWORD redirects=WINHTTP_OPTION_REDIRECT_POLICY_NEVER;
    if(!WinHttpSetOption(request.h,WINHTTP_OPTION_REDIRECT_POLICY,&redirects,sizeof(redirects)))return httpFail();
    const auto headers=record.token.empty()?std::wstring():L"x-instance-token: "+utf8ToWide(record.token)+L"\r\n";
    auto check=listeningPortsOf(clientPid);
    if(!live(client.h) || std::find(check.begin(),check.end(),record.port)==check.end())return fail("window.record_owner");
    // This is Verge's own singleton activation path, not a Win32 visibility
    // override. Tao caches VISIBLE; ShowWindowAsync bypasses that cache and
    // makes a later hide(false -> false) a no-op.
    if(!WinHttpSendRequest(request.h,headers.empty()?WINHTTP_NO_ADDITIONAL_HEADERS:headers.c_str(),
                          static_cast<DWORD>(headers.size()),WINHTTP_NO_REQUEST_DATA,0,0,0) ||
       !WinHttpReceiveResponse(request.h,nullptr))return httpFail();
    DWORD status=0,n=sizeof(status);
    if(!WinHttpQueryHeaders(request.h,WINHTTP_QUERY_STATUS_CODE|WINHTTP_QUERY_FLAG_NUMBER,
                           WINHTTP_HEADER_NAME_BY_INDEX,&status,&n,WINHTTP_NO_HEADER_INDEX))return httpFail();
    if(status!=200)return fail("window.http_"+std::to_string(status));
    std::string body;
    for(;;) { char b[16]; DWORD got=0; if(!WinHttpReadData(request.h,b,sizeof(b),&got))return httpFail();
        if(!got)break; body.append(b,got); if(body.size()>32)return fail("window.reply"); }
    check=listeningPortsOf(clientPid);
    if(!live(client.h) || std::find(check.begin(),check.end(),record.port)==check.end())return fail("window.record_owner");
    return trim(body)=="ok" || fail("window.reply");
}

uintptr_t ensureOfficialVergeWindow(uint32_t clientPid,const std::filesystem::path& dataDir,
                                   std::stop_token stop,std::string* diagnostic) {
    if(diagnostic)diagnostic->clear();
    if(!clientPid || !sameUser(clientPid) || stop.stop_requested())return 0;
    struct Windows { DWORD pid; std::vector<HWND> handles; } windows{clientPid,{}};
    auto visible=[&]{
        windows.handles.clear();
        EnumWindows([](HWND h,LPARAM p)->BOOL {
            auto& w=*reinterpret_cast<Windows*>(p); DWORD id=0; GetWindowThreadProcessId(h,&id);
            wchar_t title[256]{}; GetWindowTextW(h,title,256);
            if(id==w.pid && std::wstring_view(title).starts_with(L"Clash Verge") &&
               !GetWindow(h,GW_OWNER) && IsWindowVisible(h) && !IsIconic(h))w.handles.push_back(h);
            return TRUE;
        },reinterpret_cast<LPARAM>(&windows));
        return windows.handles.size()==1?reinterpret_cast<uintptr_t>(windows.handles.front()):uintptr_t{0};
    };
    if(auto hwnd=visible())return hwnd;
    // Activation is only needed for a hidden/minimized window. If a future
    // protocol changes, manually opening the client still makes refresh usable.
    requestOfficialVergeWindow(clientPid,dataDir,diagnostic);
    for(int i=0;i<30 && !stop.stop_requested();++i) {
        if(auto hwnd=visible())return hwnd;
        Sleep(100);
    }
    if(diagnostic && diagnostic->empty())*diagnostic="window.not_visible";
    return 0;
}

bool parseVergeProfiles(const std::string& yaml,std::string& current,std::vector<VergeProfile>& profiles) {
    current.clear(); profiles.clear(); std::istringstream input(yaml); std::string line; VergeProfile p;
    auto flush=[&]{ if(!p.uid.empty())profiles.push_back(p); p={}; };
    while(std::getline(input,line)) {
        if(line.starts_with("current:"))current=scalar(line.substr(8));
        if(line.starts_with("- uid:")) { flush(); p.uid=scalar(line.substr(6)); }
        else if(line.starts_with("  name:"))p.name=scalar(line.substr(7));
        else if(line.starts_with("  file:"))p.file=scalar(line.substr(7));
        else if(line.starts_with("  updated:"))p.updated=scalar(line.substr(10));
        else if(line.starts_with("  type:"))p.remote=scalar(line.substr(7))=="remote";
    }
    flush();
    for(size_t i=0;i<profiles.size();++i)for(size_t j=0;j<i;++j)if(profiles[i].uid==profiles[j].uid)return false;
    return !current.empty() && !profiles.empty();
}
void VergeUpdateEvidence::consume(const std::string& line) {
    const std::string marker="[订阅更新] 开始更新订阅 "; auto p=line.find(marker);
    if(p!=std::string::npos) {
        auto id=std::string(trim(line.substr(p+marker.size())));
        if(id==uid) { if(started)ambiguous=true; started=true; } else ambiguous=true;
    }
    if(ambiguous)return;
    // Newer Verge releases removed both UID/start and applied-success INFO
    // messages. A fresh generic download message is supporting evidence only;
    // the caller must independently verify the target UID/file and other items.
    if(line.find("[订阅更新]")!=std::string::npos && line.find("更新订阅配置成功")!=std::string::npos)downloaded=true;
    if(started && line.find("[订阅更新] 更新成功")!=std::string::npos)applied=true;
    if(line.find("[订阅更新] 更新失败:")!=std::string::npos ||
       line.find("所有重试均已失败")!=std::string::npos ||
       line.find("update profile failed:")!=std::string::npos)failed=true;
}

VergeSavedState verifyVergeProfileChange(const std::string& uid,
    const std::string& originalCurrent,const std::vector<VergeProfile>& before,
    const std::string& nowCurrent,const std::vector<VergeProfile>& now,bool fileChanged) {
    if(originalCurrent!=nowCurrent || before.size()!=now.size())return VergeSavedState::Conflict;
    const VergeProfile* oldTarget=nullptr; const VergeProfile* newTarget=nullptr;
    for(const auto& old:before) {
        if(std::count_if(now.begin(),now.end(),[&](const auto& p){return p.uid==old.uid;})!=1)
            return VergeSavedState::Conflict;
        const auto item=std::find_if(now.begin(),now.end(),[&](const auto& p){return p.uid==old.uid;});
        if(item->file!=old.file || item->name!=old.name || item->remote!=old.remote)
            return VergeSavedState::Conflict;
        if(old.uid==uid) {oldTarget=&old;newTarget=&*item;}
        else if(item->updated!=old.updated)return VergeSavedState::Conflict;
    }
    if(!oldTarget || !newTarget || !oldTarget->remote)return VergeSavedState::Conflict;
    auto timestamp=[](const std::string& text){
        uint64_t value=0; auto [end,err]=std::from_chars(text.data(),text.data()+text.size(),value);
        return err==std::errc{} && end==text.data()+text.size()?value:uint64_t{0};
    };
    return fileChanged && timestamp(newTarget->updated)>timestamp(oldTarget->updated)
        ?VergeSavedState::Saved:VergeSavedState::Unchanged;
}

std::string refreshOfficialVerge(const DiscoveredKernel& kernel,std::stop_token stop,const std::string& requestedUid) {
    try {
        uint32_t clientPid=0;std::filesystem::path dir;std::string identityError;
        if(!resolveOfficialVergeClient(kernel,clientPid,dir,identityError))return "error: "+identityError;
        struct RefreshLock {
            HANDLE h=nullptr; bool owned=false;
            ~RefreshLock(){if(owned)ReleaseMutex(h);if(h)CloseHandle(h);}
        } refreshLock{CreateMutexW(nullptr,FALSE,(L"Local\\APSOfficialVergeRefresh-"+std::to_wstring(clientPid)).c_str())};
        if(!refreshLock.h)return "error: 无法建立 Verge 刷新互斥保护；未执行刷新";
        const auto lockState=WaitForSingleObject(refreshLock.h,0);
        refreshLock.owned=lockState==WAIT_OBJECT_0 || lockState==WAIT_ABANDONED;
        if(lockState!=WAIT_OBJECT_0)return "error: Verge 刷新正在进行或上次中断；请先在客户端核对，未重复刷新";
        Handle core{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,kernel.pid)},client{OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION,FALSE,clientPid)};
        if(!client.h)return "error: 无法核对 Verge 客户端身份";
        const auto coreName=processNameOf(kernel.pid);
        auto coreRunning=[&]{return core.h ? live(core.h) : !coreName.empty() && equalsIgnoreCase(processNameOf(kernel.pid),coreName);};
        auto before=readFile(dir/L"profiles.yaml"); std::string current; std::vector<VergeProfile> profiles;
        if(!parseVergeProfiles(before,current,profiles))return "error: 无法安全解析 Verge 订阅列表";
        const auto uid=requestedUid.empty()?current:requestedUid;
        auto it=std::find_if(profiles.begin(),profiles.end(),[&](const auto& p){return p.uid==uid;});
        if(it==profiles.end() || !it->remote || it->name.empty())return "error: 目标不是可刷新远程订阅";
        auto target=*it; const bool isCurrent=uid==current;
        if(target.file.empty() || target.file.find_first_of("/\\:")!=std::string::npos || target.file=="..")return "error: 订阅文件路径不安全";
        const auto file=dir/L"profiles"/utf8ToWide(target.file);
        if(std::filesystem::weakly_canonical(file).parent_path()!=std::filesystem::weakly_canonical(dir/L"profiles"))return "error: 订阅文件越界";
        auto oldWrite=std::filesystem::last_write_time(file);
        if(stop.stop_requested())return "error: 刷新已取消，未操作窗口";
        std::string windowDiagnostic;
        HWND hwnd=reinterpret_cast<HWND>(ensureOfficialVergeWindow(clientPid,dir,stop,&windowDiagnostic));
        if(!hwnd)return "error: 无法打开 Verge 窗口（"+windowDiagnostic+"）；请从托盘打开订阅页，再点 APS 刷新。尚未执行订阅更新";
        ComScope scope; if(FAILED(scope.hr))return "error: UI Automation 初始化失败";
        ComPtr<IUIAutomation> ui;
        if(FAILED(CoCreateInstance(CLSID_CUIAutomation8,nullptr,CLSCTX_INPROC_SERVER,IID_PPV_ARGS(&ui))))return "error: UI Automation 不可用";
        ComPtr<IUIAutomation2> ui2; if(SUCCEEDED(ui.As(&ui2))) { ui2->put_ConnectionTimeout(2000); ui2->put_TransactionTimeout(2000); }
        ComPtr<IUIAutomationElement> root; if(FAILED(ui->ElementFromHandle(hwnd,&root)))return "error: 不能读取 Verge 窗口";
        ComPtr<IUIAutomationTreeWalker> walker; ui->get_ControlViewWalker(&walker);
        auto headings=named(ui.Get(),root.Get(),utf8ToWide(target.name)); int count=0; headings->get_Length(&count);
        if(count==0) {
            auto nav=uniqueButton(ui.Get(),root.Get(),{L"订阅",L"Subscriptions",L"Profiles"});
            if(!nav)return "error: 未识别订阅页入口（subscription.navigation）；请在官方 Verge 打开订阅页后重试";
            invoke(nav.Get());
            for(int i=0;i<15 && !stop.stop_requested();++i) { Sleep(100); headings=named(ui.Get(),root.Get(),utf8ToWide(target.name)); headings->get_Length(&count); if(count)break; }
        }
        ComPtr<IUIAutomationElement> selected; int matches=0;
        const auto day=dateOf(target.updated);
        const bool duplicate=std::count_if(profiles.begin(),profiles.end(),[&](const auto& p){return p.remote && p.name==target.name;})>1;
        if(duplicate && (day.empty() || std::count_if(profiles.begin(),profiles.end(),[&](const auto& p){return p.remote && p.name==target.name && dateOf(p.updated)==day;})!=1))
            return "error: 同名订阅不能唯一匹配，请在 Verge 中给目标订阅设置唯一名称；未刷新任何项";
        for(int i=0;i<count;++i) {
            ComPtr<IUIAutomationElement> e; headings->GetElement(i,&e);
            for(int depth=0;depth<64;++depth) {
                ComPtr<IUIAutomationElement> parent; if(FAILED(walker->GetParentElement(e.Get(),&parent)) || !parent)break;
                e=parent; auto button=uniqueButton(ui.Get(),e.Get(),{L"刷新",L"Refresh",L"刷新订阅",L"Refresh subscription",L"更新",L"Update",L"更新订阅",L"Update subscription"}); if(!button)continue;
                if(duplicate) {
                    auto dates=named(ui.Get(),e.Get(),L"更新时间: "+day+L" 点击查看下一次更新"); int n=0; dates->get_Length(&n);
                    // The UIA Name may be empty when the date is exposed as HelpText.
                    if(!n) {
                        ComPtr<IUIAutomationCondition> any; ui->CreateTrueCondition(&any); ComPtr<IUIAutomationElementArray> all;
                        e->FindAll(TreeScope_Descendants,any.Get(),&all); int total=0;if(all)all->get_Length(&total);
                        for(int j=0;j<total && j<200;++j) { ComPtr<IUIAutomationElement> child;all->GetElement(j,&child);
                            for(auto prop:{UIA_HelpTextPropertyId,UIA_FullDescriptionPropertyId}) { VARIANT v{};child->GetCurrentPropertyValue(prop,&v);
                                if(v.vt==VT_BSTR && v.bstrVal && std::wstring(v.bstrVal).find(day)!=std::wstring::npos)++n; VariantClear(&v); } }
                    }
                    if(!n)continue;
                }
                BOOL same=FALSE; if(selected)ui->CompareElements(selected.Get(),button.Get(),&same);
                if(!same){selected=button;++matches;} break;
            }
        }
        if(matches!=1)return "error: 未能唯一定位官方刷新按钮（subscription.button）；请打开订阅页并确保目标名称唯一，未执行刷新";
        if(stop.stop_requested() || !coreRunning() || !live(client.h) || readFile(dir/L"profiles.yaml")!=before)return "error: 目标状态已变化，未刷新";
        if(!vergeControllerMatchesRuntime(kernel,readFile(dir/L"clash-verge.yaml",0,4*1024*1024)))
            return "error: 运行中的控制器或代理端口已变化（subscription.identity）；未执行刷新";
        std::string controllerError;
        if(!ClashApiClient("127.0.0.1",0,kernel.apiSecret,kernel.apiPipe,kernel.pid).probe(&controllerError,1500))
            return "error: 控制管道身份已变化或暂不可用（subscription.identity）；未执行刷新";
        const auto log=dir/L"logs"/L"latest.log";
        std::error_code logError; auto offset=std::filesystem::file_size(log,logError);
        bool logAvailable=!logError;
        invoke(selected.Get());
        VergeUpdateEvidence evidence; evidence.uid=uid; std::string pending;
        const auto deadline=GetTickCount64()+120000;
        uint64_t savedAt=0;
        while(!stop.stop_requested() && GetTickCount64()<deadline) {
            if(!coreRunning() || !live(client.h))return "error: Verge 进程在刷新期间退出；结果未确认，APS 不会重启或补点";
            if(logAvailable) {
                try {auto text=readFile(log,offset);offset+=text.size();pending+=text;}
                // Log rotation, removal or a changed format must not turn a
                // verified save into a download failure. Do not read old logs.
                catch(...) {logAvailable=false;pending.clear();evidence.applied=false;}
            }
            for(size_t p;(p=pending.find('\n'))!=std::string::npos;) { evidence.consume(pending.substr(0,p));pending.erase(0,p+1); }
            if(evidence.ambiguous)return "error: 检测到并发订阅操作；结果无法归属于本次请求，请在客户端核对";
            std::string nowCurrent;std::vector<VergeProfile> now;
            if(!parseVergeProfiles(readFile(dir/L"profiles.yaml"),nowCurrent,now) || nowCurrent!=current)return "error: 当前订阅发生变化，请在客户端核对；APS 未切换订阅";
            const auto saved=verifyVergeProfileChange(uid,current,profiles,nowCurrent,now,
                                                      std::filesystem::last_write_time(file)!=oldWrite);
            if(saved==VergeSavedState::Conflict)return "error: 订阅列表或其他订阅同时发生变化；请在 Verge 核对本次结果，未重复刷新";
            if(evidence.failed)return saved==VergeSavedState::Saved
                ?"warning: Verge 已保存订阅，但客户端报告后续操作失败；请在 Verge 核对应用状态，未重复刷新"
                :"error: Verge 报告订阅更新失败；请查看客户端详情，未重复刷新";
            if(saved==VergeSavedState::Saved) {
                if(!savedAt)savedAt=GetTickCount64();
                BOOL enabled=FALSE;
                const bool finished=SUCCEEDED(selected->get_CurrentIsEnabled(&enabled)) && enabled;
                if(finished && GetTickCount64()-savedAt>=1000) {
                    if(isCurrent && evidence.started && evidence.downloaded && evidence.applied)
                        return "ok: 官方 Verge 已下载、保存并应用当前订阅；进程未重启、APS 出口未切换";
                    if(isCurrent)return "warning: 已确认当前订阅文件和更新时间更新；Verge 刷新已结束，内核应用结果请在客户端核对。未重复刷新或切换出口";
                    return evidence.downloaded
                        ?"ok: 官方 Verge 已下载并保存目标订阅；未激活该订阅、进程未重启"
                        :"ok: 已确认目标订阅文件和更新时间更新；未激活该订阅、进程未重启";
                }
            } else savedAt=0;
            Sleep(200);
        }
        if(savedAt)return "warning: 已确认订阅文件和更新时间更新；客户端后续操作结果未确认，请在 Verge 核对，未重复刷新";
        return "error: 官方 Verge 更新结果未确认，请查看客户端；APS 不会重复点击或重启内核";
    } catch(const std::filesystem::filesystem_error&) {
        return "error: Verge 文件读取异常；请在客户端核对，不会自动重试或重启";
    } catch(const std::runtime_error& e) {
        return "error: "+std::string(e.what());
    } catch(const std::exception& e) {
        // Only our fixed messages cross the status channel; filesystem errors
        // could include user paths and are deliberately not forwarded.
        (void)e; return "error: 官方 Verge 更新未确认（读取/界面调用异常）；请查看客户端，不会自动重试或重启";
    }
}
}
