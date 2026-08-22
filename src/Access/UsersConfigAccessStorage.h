#pragma once

#include <Access/MemoryAccessStorage.h>
#include <Access/UsersConfigParser.h>
#include <Common/ZooKeeper/Common.h>


namespace Poco::Util
{
    class AbstractConfiguration;
}


namespace DB
{
class AccessControl;
class ConfigReloader;

/// Implementation of IAccessStorage which loads all from users.xml periodically.
/// Should be initialized after disk storage was added to AccessControl so that roles can be
/// referenced in users.xml grants.
class UsersConfigAccessStorage : public IAccessStorage
{
public:
    static constexpr char STORAGE_TYPE[] = "users_xml";

    UsersConfigAccessStorage(const String & storage_name_, AccessControl & access_control_, bool allow_backup_);
    ~UsersConfigAccessStorage() override;

    const char * getStorageType() const override { return STORAGE_TYPE; }
    String getStorageParamsJSON() const override;
    bool isReadOnly() const override { return true; }

    String getPath() const;
    bool isPathEqual(const String & path_) const;

    void setConfig(const Poco::Util::AbstractConfiguration & config);
    void load(const String & users_config_path,
              const String & include_from_path = {},
              const String & preprocessed_dir = {},
              const zkutil::GetZooKeeper & get_zookeeper_function = {});

    void startPeriodicReloading() override;
    void stopPeriodicReloading() override;
    void reload(ReloadMode reload_mode) override;

    bool exists(const UUID & id) const override;

    bool isBackupAllowed() const override { return backup_allowed; }

private:
    std::vector<std::pair<UUID, AccessEntityPtr>>
    parseFromConfig(const Poco::Util::AbstractConfiguration & config, const String & config_path) const;
    std::optional<UUID> findImpl(AccessEntityType type, const String & name) const override;
    std::vector<UUID> findAllImpl(AccessEntityType type) const override;
    AccessEntityPtr readImpl(const UUID & id, bool throw_if_not_exists) const override;
    std::optional<std::pair<String, AccessEntityType>> readNameWithTypeImpl(const UUID & id, bool throw_if_not_exists) const override;

    AccessControl & access_control;
    MemoryAccessStorage memory_storage;
    String path TSA_GUARDED_BY(load_mutex);
    std::unique_ptr<ConfigReloader> config_reloader TSA_GUARDED_BY(reconfiguration_mutex);
    bool backup_allowed = false;
    mutable std::mutex load_mutex;
    mutable std::mutex reconfiguration_mutex;
};
}
