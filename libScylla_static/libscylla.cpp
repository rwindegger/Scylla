#include "libscylla.h"
#include "native_win_api.h"

#include "iat_searcher.h"

#include "configuration_holder.h"
#include "configuration.h"

#include "Logger.h"
#include "Architecture.h"

#include "PluginLoader.h"
#include "ImportRebuilder.h"
#include "Thunks.h"

LPCTSTR libscylla::get_version_information()
{
    return APPNAME TEXT(" ") ARCHITECTURE TEXT(" ") APPVERSION;
}

DWORD libscylla::get_version()
{
    return APPVERSIONDWORD;
}

std::shared_ptr<native_win_api> libscylla::windows_api() {
    static std::shared_ptr<native_win_api> instance{ std::make_shared<native_win_api>() };
    return instance;
};

std::shared_ptr<libscylla> libscylla::create(std::shared_ptr<Logger> log, pid_t target_pid, bool is_standalone)
{
    std::shared_ptr<libscylla> result{ new libscylla(log, target_pid, is_standalone) };
    result->initialize(result);
    return result;
}

libscylla::libscylla(std::shared_ptr<Logger> log, pid_t target_pid, bool is_standalone)
    : log_{ std::move(log) }
    , config_{ std::make_shared<configuration_holder>(TEXT("Scylla.ini")) }
    , plugins_{ std::make_unique<PluginLoader>() }
    , pid_{ target_pid }
    , is_standalone_{ is_standalone }
    , selected_module_{ nullptr }
{
    if (is_standalone_)
    {
        config_->loadConfiguration();
        plugins_->findAllPlugins();
    }
}
libscylla::~libscylla() = default;

void libscylla::initialize(std::shared_ptr<libscylla> self)
{
    local_api_reader_ = std::make_shared<iat_searcher>(self, GetCurrentProcessId());
    target_api_reader_ = std::make_shared<iat_searcher>(self);

    update_local_information();
    update_target_information();
}

void libscylla::log(scylla_severity severity, LPCTSTR format, ...) const
{
    if (severity < scylla_severity::information)
        return;

    if (!format)
        return;

    va_list va_alist;
    va_start(va_alist, format);
    log_->log(format, va_alist);
    va_end(va_alist);
}

pid_t libscylla::target_pid() const
{
    return pid_;
}

std::shared_ptr<configuration_holder> libscylla::config() const
{
    return config_;
}

const std::vector<std::shared_ptr<module_info>> *libscylla::local_modules() const
{
    return &local_modules_;
}

const std::unordered_multimap<uintptr_t, std::shared_ptr<api_info>> *libscylla::local_apis() const
{
    return &local_apis_;
}

const std::vector<std::shared_ptr<module_info>> *libscylla::target_modules() const
{
    return &target_modules_;
}

const std::unordered_multimap<uintptr_t, std::shared_ptr<api_info>> *libscylla::target_apis() const
{
    return &target_apis_;
}

void libscylla::add_target_api_by_virtual_address(uintptr_t virtual_address, uintptr_t iat_address, bool* is_suspect)
{
    auto api_info = target_api_reader_->get_api_by_virtual_address(virtual_address, is_suspect);
    target_api_reader_->add_found_api_to_module_list(iat_address, api_info, true, *is_suspect, target_thunks_);
}

std::shared_ptr<iat_searcher> libscylla::local_api_reader() const
{
    return local_api_reader_;
};

std::shared_ptr<iat_searcher> libscylla::target_api_reader() const
{
    return target_api_reader_;
};

iat_search_result libscylla::iat_search(uintptr_t search_start, bool advanced_search)
{
    update_local_information();
    update_target_information();
    
    iat_search_result retVal{};
    retVal.status = scylla_status::iat_not_found;

    if (target_api_reader_->search_import_address_table_remote(search_start, &retVal.start, &retVal.size, advanced_search))
    {
        target_api_reader_->read_and_parse_iat(retVal.start, retVal.size, target_thunks_);
        retVal.status = scylla_status::success;
    }

    return retVal;
}

scylla_status libscylla::iat_auto_fix(uintptr_t iat_address, size_t iat_size, LPCTSTR dump_file, LPCTSTR iat_fix_file)
{
    update_local_information();
    update_target_information();

    target_thunks_.clear();
    target_api_reader_->read_and_parse_iat(iat_address, iat_size, target_thunks_);
    
    //add IAT section to dump
    ImportRebuilder importRebuild(dump_file);
    importRebuild.enableOFTSupport();

    scylla_status retVal = scylla_status::iat_write_failed;

    if (importRebuild.rebuildImportTable(iat_fix_file, target_thunks_))
    {
        retVal = scylla_status::success;
    }

    return retVal;
}

void libscylla::update_local_information()
{
    local_modules_.clear();
    local_apis_.clear();
    local_api_reader_->get_process_modules(local_modules_);
    local_api_reader_->read_apis_from_module_list(local_modules_, local_apis_);
}

void libscylla::update_target_information()
{
    target_modules_.clear();
    target_apis_.clear();
    target_api_reader_->get_process_modules(target_modules_);
    target_api_reader_->read_apis_from_module_list(target_modules_, target_apis_);
    selected_module_ = nullptr;
}
