#include <Access/AccessBackup.h>
#include <Access/AccessControl.h>
#include <Access/AccessEntityIO.h>
#include <Access/Common/AccessRightsElement.h>
#include <Access/User.h>
#include <Access/Role.h>
#include <Access/SettingsProfile.h>
#include <Access/RowPolicy.h>
#include <Access/MaskingPolicy.h>
#include <Access/Quota.h>
#include <Backups/BackupEntriesCollector.h>
#include <Backups/BackupEntryFromMemory.h>
#include <Backups/IBackup.h>
#include <Backups/RestoreSettings.h>
#include <IO/WriteHelpers.h>
#include <IO/ReadHelpers.h>
#include <IO/ReadBufferFromString.h>
#include <Poco/UUIDGenerator.h>
#include <base/insertAtEnd.h>

#include <boost/range/adaptor/map.hpp>
#include <boost/range/algorithm/copy.hpp>
#include <Core/UUID.h>

namespace fs = std::filesystem;


namespace DB
{

namespace ErrorCodes
{
    extern const int CANNOT_RESTORE_TABLE;
    extern const int ACCESS_ENTITY_ALREADY_EXISTS;
    extern const int ACCESS_ENTITY_NOT_FOUND;
    extern const int LOGICAL_ERROR;
}


namespace
{
    /// Represents a list of access entities as they're stored in a backup.
    struct AccessEntitiesInBackup
    {
        std::unordered_map<UUID, AccessEntityPtr> entities;
        std::unordered_map<UUID, std::pair<String, AccessEntityType>> dependencies;
        std::unordered_map<UUID, AccessEntityPtr> dependents;

        BackupEntryPtr toBackupEntry() const
        {
            WriteBufferFromOwnString buf;

            for (const auto & [id, entity] : entities)
            {
                writeText(id, buf);
                writeChar('\t', buf);
                writeText(entity->getTypeInfo().name, buf);
                writeChar('\t', buf);
                writeText(entity->getName(), buf);
                writeChar('\n', buf);
                writeText(serializeAccessEntity(*entity), buf);
                writeChar('\n', buf);
            }

            if (!dependencies.empty())
            {
                writeText("DEPENDENCIES\n", buf);
                for (const auto & [id, name_and_type] : dependencies)
                {
                    writeText(id, buf);
                    writeChar('\t', buf);
                    writeText(AccessEntityTypeInfo::get(name_and_type.second).name, buf);
                    writeChar('\t', buf);
                    writeText(name_and_type.first, buf);
                    writeChar('\n', buf);
                }
            }

            if (!dependents.empty())
            {
                if (!dependencies.empty())
                    writeText("\n", buf);
                writeText("DEPENDENTS\n", buf);
                for (const auto & [id, entity] : dependents)
                {
                    writeText(id, buf);
                    writeChar('\t', buf);
                    writeText(entity->getTypeInfo().name, buf);
                    writeChar('\t', buf);
                    writeText(entity->getName(), buf);
                    writeChar('\n', buf);
                    writeText(serializeAccessEntity(*entity), buf);
                    writeChar('\n', buf);
                }
            }

            return std::make_shared<BackupEntryFromMemory>(buf.str());
        }

        static AccessEntitiesInBackup fromBackupEntry(std::unique_ptr<ReadBuffer> buf, const String & file_path)
        {
            try
            {
                AccessEntitiesInBackup res;

                bool reading_dependencies = false;
                bool reading_dependents = false;

                while (!buf->eof())
                {
                    String line;
                    readStringUntilNewlineInto(line, *buf);
                    buf->ignore();

                    if (line == "DEPENDENCIES")
                    {
                        reading_dependencies = true;
                        reading_dependents = false;
                        continue;
                    }
                    if (line == "DEPENDENTS")
                    {
                        reading_dependents = true;
                        reading_dependencies = false;
                        continue;
                    }
                    if (line.empty())
                        continue;

                    size_t separator1 = line.find('\t');
                    size_t separator2 = line.find('\t', separator1 + 1);
                    if ((separator1 == String::npos) || (separator2 == String::npos))
                        throw Exception(ErrorCodes::CANNOT_RESTORE_TABLE, "Separators not found in line {}", line);

                    UUID id = parse<UUID>(line.substr(0, separator1));
                    AccessEntityType type = AccessEntityTypeInfo::parseType(line.substr(separator1 + 1, separator2 - separator1 - 1));
                    String name = line.substr(separator2 + 1);

                    if (reading_dependencies)
                    {
                        auto [it, inserted] = res.dependencies.emplace(id, std::pair{name, type});
                        if (!inserted && (it->second != std::pair{name, type}))
                            throw Exception(ErrorCodes::CANNOT_RESTORE_TABLE, "Conflicting dependency metadata for UUID {}", id);
                    }
                    else
                    {
                        String queries;
                        while (!buf->eof())
                        {
                            String query;
                            readStringUntilNewlineInto(query, *buf);
                            buf->ignore();
                            if (query.empty())
                                break;
                            if (!queries.empty())
                                queries.append("\n");
                            queries.append(query);
                        }

                        AccessEntityPtr entity = deserializeAccessEntity(queries);

                        if (name != entity->getName())
                            throw Exception(ErrorCodes::CANNOT_RESTORE_TABLE, "Unexpected name {} is specified for {}", name, entity->formatTypeWithName());
                        if (type != entity->getType())
                            throw Exception(ErrorCodes::CANNOT_RESTORE_TABLE, "Unexpected type {} is specified for {}", AccessEntityTypeInfo::get(type).name, entity->formatTypeWithName());

                        auto & destination = reading_dependents ? res.dependents : res.entities;
                        auto [it, inserted] = destination.emplace(id, entity);
                        if (!inserted && (*it->second != *entity))
                            throw Exception(ErrorCodes::CANNOT_RESTORE_TABLE, "Conflicting definitions for UUID {}", id);
                    }
                }

                return res;
            }
            catch (Exception & e)
            {
                e.addMessage("While parsing " + file_path + " from backup");
                throw;
            }
        }
    };
}


std::pair<String, BackupEntryPtr> makeBackupEntryForAccessEntities(
    const std::vector<UUID> & entities_ids,
    const std::unordered_map<UUID, AccessEntityPtr> & all_entities,
    bool write_dependents,
    const String & data_path_in_backup)
{
    AccessEntitiesInBackup ab;

    std::unordered_set<UUID> entities_ids_set;
    for (const auto & id : entities_ids)
        entities_ids_set.emplace(id);

    for (const auto & id : entities_ids)
    {
        auto it = all_entities.find(id);
        if (it != all_entities.end())
        {
            AccessEntityPtr entity = it->second;
            ab.entities.emplace(id, entity);

            auto dependencies = entity->findDependencies();
            for (const auto & dependency_id : dependencies)
            {
                if (!entities_ids_set.contains(dependency_id))
                {
                    auto it_dependency = all_entities.find(dependency_id);
                    if (it_dependency != all_entities.end())
                    {
                        auto dependency_entity = it_dependency->second;
                        ab.dependencies.emplace(dependency_id, std::make_pair(dependency_entity->getName(), dependency_entity->getType()));
                    }
                }
            }
        }
    }

    if (write_dependents)
    {
        for (const auto & [id, possible_dependent] : all_entities)
        {
            if (!entities_ids_set.contains(id) && possible_dependent->hasDependencies(entities_ids_set))
            {
                auto dependent = possible_dependent->clone();
                dependent->clearAllExceptDependencies();
                ab.dependents.emplace(id, dependent);
            }
        }
    }

    String filename = fmt::format("access-{}.txt", UUIDHelpers::generateV4());
    String file_path_in_backup = fs::path{data_path_in_backup} / filename;
    return {file_path_in_backup, ab.toBackupEntry()};
}


AccessRestorerFromBackup::AccessRestorerFromBackup(
    const BackupPtr & backup_, const RestoreSettings & restore_settings_)
    : backup(backup_)
    , creation_mode(restore_settings_.create_access)
    , skip_unresolved_dependencies(restore_settings_.skip_unresolved_access_dependencies)
    , update_dependents(restore_settings_.update_access_entities_dependents)
    , restore_with_current_grants(restore_settings_.restore_access_entities_with_current_grants)
    , log(getLogger("AccessRestorerFromBackup"))
{
}

AccessRestorerFromBackup::~AccessRestorerFromBackup() = default;


void AccessRestorerFromBackup::addDataPath(const String & data_path_in_backup)
{
    if (loaded)
        throw Exception(ErrorCodes::LOGICAL_ERROR, "Access entities already loaded");

    if (std::find(data_paths_in_backup.begin(), data_paths_in_backup.end(), data_path_in_backup) == data_paths_in_backup.end())
        data_paths_in_backup.emplace_back(data_path_in_backup);
}


void AccessRestorerFromBackup::loadFromBackup()
{
    if (loaded)
        return;

    decltype(entity_infos) loaded_entity_infos;
    auto get_or_add_entity_info = [&](const UUID & id, const String & name, AccessEntityType type, const String & filepath) -> EntityInfo &
    {
        auto [it, inserted] = loaded_entity_infos.emplace(id, EntityInfo{.id = id, .name = name, .type = type});
        EntityInfo & entity_info = it->second;
        if (!inserted && ((entity_info.name != name) || (entity_info.type != type)))
        {
            throw Exception(
                ErrorCodes::CANNOT_RESTORE_TABLE,
                "Conflicting metadata for UUID {}: {} and {} while reading {}",
                id,
                AccessEntityTypeInfo::get(entity_info.type).formatEntityNameWithType(entity_info.name),
                AccessEntityTypeInfo::get(type).formatEntityNameWithType(name),
                filepath);
        }
        return entity_info;
    };

    /// Parse files "access*.txt" found in the added data paths in the backup.
    for (size_t data_path_index = 0; data_path_index != data_paths_in_backup.size(); ++data_path_index)
    {
        const String & data_path_in_backup = data_paths_in_backup[data_path_index];

        fs::path data_path_in_backup_fs = data_path_in_backup;
        Strings filenames = backup->listFiles(data_path_in_backup_fs, /*recursive*/ false);
        if (filenames.empty())
            continue;

        for (const String & filename : filenames)
        {
            if (!filename.starts_with("access") || !filename.ends_with(".txt"))
                throw Exception(ErrorCodes::CANNOT_RESTORE_TABLE, "File name {} doesn't match the wildcard \"access*.txt\"",
                                String{data_path_in_backup_fs / filename});
        }

        for (const String & filename : filenames)
        {
            String filepath_in_backup = data_path_in_backup_fs / filename;
            AccessEntitiesInBackup ab;

            try
            {
                auto read_buffer_from_backup = backup->readFile(filepath_in_backup);
                ab = AccessEntitiesInBackup::fromBackupEntry(std::move(read_buffer_from_backup), filepath_in_backup);
            }
            catch (Exception & e)
            {
                e.addMessage("While reading access entities from {} in backup", filepath_in_backup);
                throw;
            }

            for (const auto & [id, entity] : ab.entities)
            {
                EntityInfo & entity_info = get_or_add_entity_info(id, entity->getName(), entity->getType(), filepath_in_backup);
                if (entity_info.restore)
                {
                    if (*entity_info.entity != *entity)
                        throw Exception(
                            ErrorCodes::CANNOT_RESTORE_TABLE,
                            "Conflicting definitions for UUID {} while reading {}",
                            id,
                            filepath_in_backup);
                    continue;
                }
                entity_info.entity = entity;
                entity_info.restore = true;
                entity_info.data_path_index = data_path_index;
            }

            for (const auto & [id, name_and_type] : ab.dependencies)
            {
                EntityInfo & entity_info = get_or_add_entity_info(id, name_and_type.first, name_and_type.second, filepath_in_backup);
                entity_info.is_dependency = true;
            }

            for (const auto & [id, entity] : ab.dependents)
            {
                EntityInfo & entity_info = get_or_add_entity_info(id, entity->getName(), entity->getType(), filepath_in_backup);
                if (entity_info.restore)
                    continue;

                if (!entity_info.entity)
                {
                    entity_info.entity = entity;
                    continue;
                }

                std::unordered_set<UUID> incoming_dependencies;
                for (const auto & dependency_id : entity->findDependencies())
                    incoming_dependencies.emplace(dependency_id);

                std::unordered_set<UUID> existing_dependencies;
                for (const auto & dependency_id : entity_info.entity->findDependencies())
                    existing_dependencies.emplace(dependency_id);

                std::unordered_set<UUID> overlapping_dependencies;
                for (const auto & dependency_id : incoming_dependencies)
                {
                    if (existing_dependencies.contains(dependency_id))
                        overlapping_dependencies.emplace(dependency_id);
                }

                if (!overlapping_dependencies.empty())
                {
                    auto keep_only_dependencies = [](const AccessEntityPtr & source, const std::unordered_set<UUID> & ids_to_keep)
                    {
                        auto result = source->clone();
                        std::unordered_set<UUID> ids_to_remove;
                        for (const auto & dependency_id : source->findDependencies())
                        {
                            if (!ids_to_keep.contains(dependency_id))
                                ids_to_remove.emplace(dependency_id);
                        }
                        result->removeDependencies(ids_to_remove);
                        return result;
                    };

                    auto existing_overlap = keep_only_dependencies(entity_info.entity, overlapping_dependencies);
                    auto incoming_overlap = keep_only_dependencies(entity, overlapping_dependencies);
                    if (*existing_overlap != *incoming_overlap)
                    {
                        throw Exception(
                            ErrorCodes::CANNOT_RESTORE_TABLE,
                            "Conflicting dependent definitions for UUID {} while reading {}",
                            id,
                            filepath_in_backup);
                    }
                }

                std::unordered_set<UUID> dependencies_to_copy = std::move(incoming_dependencies);
                for (const auto & dependency_id : existing_dependencies)
                    dependencies_to_copy.erase(dependency_id);

                if (!dependencies_to_copy.empty())
                {
                    auto merged_entity = entity_info.entity->clone();
                    merged_entity->copyDependenciesFrom(*entity, dependencies_to_copy);

                    std::unordered_set<UUID> merged_dependencies;
                    for (const auto & dependency_id : merged_entity->findDependencies())
                        merged_dependencies.emplace(dependency_id);
                    for (const auto & dependency_id : dependencies_to_copy)
                    {
                        if (!merged_dependencies.contains(dependency_id))
                        {
                            throw Exception(
                                ErrorCodes::CANNOT_RESTORE_TABLE,
                                "Conflicting dependent definitions for UUID {} while reading {}",
                                id,
                                filepath_in_backup);
                        }
                    }

                    entity_info.entity = std::move(merged_entity);
                }
            }
        }
    }

    entity_infos = std::move(loaded_entity_infos);
    loaded = true;
}


AccessRightsElements AccessRestorerFromBackup::getRequiredAccess() const
{
    if (!loaded)
        throw Exception(ErrorCodes::LOGICAL_ERROR, "Access entities not loaded");

    AccessRightsElements res;
    std::unordered_set<UUID> ids_to_restore;
    for (const auto & [id, entity_info] : entity_infos)
    {
        if (entity_info.restore)
            ids_to_restore.emplace(id);
    }

    for (const auto & [id, entity_info] : entity_infos)
    {
        if (!entity_info.restore)
            continue;
        const auto & entity = entity_info.entity;
        auto entity_type = entity->getType();
        switch (entity_type)
        {
            case User::TYPE:
            {
                const auto & user = typeid_cast<const User &>(*entity);
                res.emplace_back(AccessType::CREATE_USER, user.getName());
                if (!restore_with_current_grants)
                {
                    auto elements = user.access.getElements();
                    for (auto & element : elements)
                    {
                        if (!element.is_partial_revoke)
                            element.grant_option = true;
                        res.emplace_back(element);
                    }
                }
                if (!user.granted_roles.isEmpty())
                    res.emplace_back(AccessType::ROLE_ADMIN);
                break;
            }

            case Role::TYPE:
            {
                const auto & role = typeid_cast<const Role &>(*entity);
                res.emplace_back(AccessType::CREATE_ROLE, role.getName());
                if (!restore_with_current_grants)
                {
                    auto elements = role.access.getElements();
                    for (auto & element : elements)
                    {
                        if (!element.is_partial_revoke)
                            element.grant_option = true;
                        res.emplace_back(element);
                    }
                }
                if (!role.granted_roles.isEmpty())
                    res.emplace_back(AccessType::ROLE_ADMIN);
                break;
            }

            case SettingsProfile::TYPE:
            {
                res.emplace_back(AccessType::CREATE_SETTINGS_PROFILE);
                break;
            }

            case RowPolicy::TYPE:
            {
                const auto & policy = typeid_cast<const RowPolicy &>(*entity);
                res.emplace_back(AccessType::CREATE_ROW_POLICY, policy.getDatabase(), policy.getTableName());
                break;
            }

            case Quota::TYPE:
            {
                res.emplace_back(AccessType::CREATE_QUOTA);
                break;
            }

            case MaskingPolicy::TYPE:
            {
                res.emplace_back(AccessType::CREATE_MASKING_POLICY);
                break;
            }

            default:
                throw Exception(ErrorCodes::LOGICAL_ERROR, "Unknown type: {}", toString(entity_type));
        }
    }

    if (!update_dependents)
        return res;

    for (const auto & [id, entity_info] : entity_infos)
    {
        /// With `kCreateIfNotExists`, an entity selected for restoration can turn out to
        /// exist and then be updated as a dependent. Other non-restored entity snapshots
        /// are dependents directly. `kCreate` fails on an existing entity and `kReplace`
        /// replaces it, so neither mode needs an additional alter permission here.
        const bool may_update_existing = !entity_info.restore || (creation_mode == RestoreAccessCreationMode::kCreateIfNotExists);
        if (!may_update_existing || !entity_info.entity || !entity_info.entity->hasDependencies(ids_to_restore))
            continue;

        const auto & entity = entity_info.entity;
        switch (entity->getType())
        {
            case User::TYPE:
            {
                const auto & user = typeid_cast<const User &>(*entity);
                res.emplace_back(AccessType::ALTER_USER, user.getName());
                if (user.granted_roles.hasDependencies(ids_to_restore))
                    res.emplace_back(AccessType::ROLE_ADMIN);
                break;
            }

            case Role::TYPE:
            {
                const auto & role = typeid_cast<const Role &>(*entity);
                res.emplace_back(AccessType::ALTER_ROLE, role.getName());
                if (role.granted_roles.hasDependencies(ids_to_restore))
                    res.emplace_back(AccessType::ROLE_ADMIN);
                break;
            }

            case SettingsProfile::TYPE:
                res.emplace_back(AccessType::ALTER_SETTINGS_PROFILE);
                break;

            case RowPolicy::TYPE:
            {
                const auto & policy = typeid_cast<const RowPolicy &>(*entity);
                res.emplace_back(AccessType::ALTER_ROW_POLICY, policy.getDatabase(), policy.getTableName());
                break;
            }

            case Quota::TYPE:
                res.emplace_back(AccessType::ALTER_QUOTA);
                break;

            case MaskingPolicy::TYPE:
                res.emplace_back(AccessType::ALTER_MASKING_POLICY);
                break;

            default:
                throw Exception(ErrorCodes::LOGICAL_ERROR, "Unknown type: {}", toString(entity->getType()));
        }
    }

    return res;
}


void AccessRestorerFromBackup::generateRandomIDsAndResolveDependencies(const AccessControl & access_control)
{
    if (ids_assigned)
        return;

    if (!loaded)
        throw Exception(ErrorCodes::LOGICAL_ERROR, "Access entities not loaded");

    /// Calculate `new_id` for each entity info.
    /// Check which ones of the loaded access entities already exist.
    /// Generate random UUIDs for access entities which we're going to restore if they don't exist.
    for (auto & [id, entity_info] : entity_infos)
    {
        const String & name = entity_info.name;
        auto type = entity_info.type;

        if (entity_info.restore && (creation_mode == RestoreAccessCreationMode::kReplace))
        {
            entity_info.new_id = UUIDHelpers::generateV4();
            LOG_TRACE(log, "{}: Generated new UUID {}", AccessEntityTypeInfo::get(type).formatEntityNameWithType(name), *entity_info.new_id);
            continue;
        }

        if (auto existing_id = access_control.find(type, name))
        {
            if (entity_info.restore && (creation_mode == RestoreAccessCreationMode::kCreate))
            {
                throw Exception(ErrorCodes::ACCESS_ENTITY_ALREADY_EXISTS, "Cannot restore {} because it already exists",
                                AccessEntityTypeInfo::get(type).formatEntityNameWithType(name));
            }
            bool was_going_to_restore = entity_info.restore;
            entity_info.new_id = *existing_id;
            entity_info.restore = false;
            LOG_TRACE(log, "{}: Found with UUID {}{}", AccessEntityTypeInfo::get(type).formatEntityNameWithType(name), *existing_id,
                      (was_going_to_restore ? ", will not restore" : ""));
        }
        else
        {
            if (entity_info.restore)
            {
                entity_info.new_id = UUIDHelpers::generateV4();
                LOG_TRACE(log, "{}: Generated new UUID {}", AccessEntityTypeInfo::get(type).formatEntityNameWithType(name), *entity_info.new_id);
            }
            else if (skip_unresolved_dependencies)
            {
                LOG_TRACE(log, "{}: Not found, ignoring", AccessEntityTypeInfo::get(type).formatEntityNameWithType(name));
            }
            else
            {
                throw Exception(ErrorCodes::ACCESS_ENTITY_NOT_FOUND, "Cannot resolve {} while restoring from backup",
                                AccessEntityTypeInfo::get(type).formatEntityNameWithType(name));
            }
        }
    }

    /// Prepare map from old UUIDs to new UUIDs.
    std::unordered_set<UUID> ids_to_restore;
    std::unordered_map<UUID, UUID> old_to_new_ids;
    std::unordered_set<UUID> unresolved_ids;

    for (const auto & [id, entity_info] : entity_infos)
    {
        if (entity_info.restore)
            ids_to_restore.insert(id);

        if (entity_info.new_id)
            old_to_new_ids[id] = *entity_info.new_id;
        else
            unresolved_ids.insert(id);
    }

    /// Calculate `is_dependent` for each entity info.
    if (update_dependents)
    {
        for (auto & [id, entity_info] : entity_infos)
        {
            if (!entity_info.restore && entity_info.new_id && entity_info.entity && entity_info.entity->hasDependencies(ids_to_restore))
                entity_info.is_dependent = true;
        }
    }

    /// Remap the UUIDs of dependencies in the access entities we're going to restore.
    for (auto & [id, entity_info] : entity_infos)
    {
        if (entity_info.restore || entity_info.is_dependent)
        {
            auto new_entity = entity_info.entity->clone();
            new_entity->replaceDependencies(old_to_new_ids);
            new_entity->removeDependencies(unresolved_ids);
            entity_info.entity = new_entity;
        }

        if (entity_info.restore && data_path_with_entities_to_restore.empty())
            data_path_with_entities_to_restore = data_paths_in_backup[entity_info.data_path_index];
    }

    ids_assigned = true;
}


AccessEntitiesToRestore AccessRestorerFromBackup::getEntitiesToRestore(const String & data_path_in_backup) const
{
    if (!ids_assigned)
        throw Exception(ErrorCodes::LOGICAL_ERROR, "IDs not assigned");

    if (data_path_in_backup != data_path_with_entities_to_restore)
        return {};

    AccessEntitiesToRestore res;
    res.new_entities.reserve(entity_infos.size());
    res.dependents.reserve(entity_infos.size());

    for (const auto & [id, entity_info] : entity_infos)
    {
        if (entity_info.restore)
            res.new_entities.emplace_back(*entity_info.new_id, entity_info.entity);

        if (entity_info.is_dependent)
            res.dependents.emplace_back(AccessEntitiesToRestore::Dependent{*entity_info.new_id, entity_info.entity});
    }

    return res;
}


void restoreAccessEntitiesFromBackup(
    IAccessStorage & destination_access_storage,
    const AccessEntitiesToRestore & entities_to_restore,
    const RestoreSettings & restore_settings)
{
    if (entities_to_restore.new_entities.empty())
        return; /// Nothing to restore.

    auto log = getLogger("AccessRestorerFromBackup");

    bool replace_if_exists = (restore_settings.create_access == RestoreAccessCreationMode::kReplace);
    bool throw_if_exists = (restore_settings.create_access == RestoreAccessCreationMode::kCreate);
    bool update_dependents = restore_settings.update_access_entities_dependents;

    std::unordered_set<UUID> restored_ids;
    std::unordered_map<UUID, UUID> new_to_existing_ids;
    AccessEntitiesToRestore::Dependents additional_dependents;
    additional_dependents.reserve(entities_to_restore.new_entities.size());

    for (const auto & [id, entity] : entities_to_restore.new_entities)
    {
        const String & name = entity->getName();
        auto type = entity->getType();
        LOG_TRACE(log, "{}: Adding with UUID {}", AccessEntityTypeInfo::get(type).formatEntityNameWithType(name), id);

        UUID existing_id;
        if (destination_access_storage.insert(id, entity, replace_if_exists, throw_if_exists, &existing_id))
        {
            LOG_TRACE(log, "{}: Added successfully", AccessEntityTypeInfo::get(type).formatEntityNameWithType(name));
            restored_ids.emplace(id);
        }
        else
        {
            /// Couldn't insert `entity` because there is an existing entity with the same name.
            LOG_TRACE(log, "{}: Not added because already exists with UUID {}", AccessEntityTypeInfo::get(type).formatEntityNameWithType(name), existing_id);
            new_to_existing_ids[id] = existing_id;
            if (update_dependents)
                additional_dependents.emplace_back(AccessEntitiesToRestore::Dependent{existing_id, entity});
        }
    }

    if (!new_to_existing_ids.empty())
    {
        std::vector<UUID> ids_to_update;
        ids_to_update.reserve(restored_ids.size());
        boost::copy(restored_ids, std::inserter(ids_to_update, ids_to_update.end()));

        std::unordered_set<UUID> new_ids;
        boost::copy(new_to_existing_ids | boost::adaptors::map_keys, std::inserter(new_ids, new_ids.end()));

        /// If new entities restored from backup have dependencies on other entities from backup which were not restored because they existed,
        /// then we should correct those dependencies.
        auto update_func = [&](const AccessEntityPtr & entity, const UUID &) -> AccessEntityPtr
        {
            if (!entity->hasDependencies(new_ids))
                return entity;
            LOG_TRACE(log, "{}: Updating dependencies", entity->formatTypeWithName());
            auto res = entity->clone();
            res->replaceDependencies(new_to_existing_ids);
            return res;
        };

        /// It's totally ok if some UUIDs from `ids_to_update` don't exist anymore, that's why we use tryUpdate() here.
        destination_access_storage.tryUpdate(ids_to_update, update_func);
    }

    auto do_update_dependents = [&](const AccessEntitiesToRestore::Dependents & dependents)
    {
        if (dependents.empty())
            return;

        std::vector<UUID> ids_to_update;
        ids_to_update.reserve(dependents.size());
        std::unordered_map<UUID, AccessEntityPtr> id_to_source;

        for (const auto & dependent : dependents)
        {
            const UUID & id = dependent.existing_id;
            if (!destination_access_storage.isReadOnly(id))
            {
                ids_to_update.emplace_back(id);
                auto modified_source = dependent.source->clone();
                modified_source->replaceDependencies(new_to_existing_ids);
                id_to_source[id] = modified_source;
            }
        }

        /// If new entities restored from backup have dependencies on other entities from backup which were not restored because they existed,
        /// then we should correct those dependencies.
        auto update_func = [&](const AccessEntityPtr & entity, const UUID & existing_id) -> AccessEntityPtr
        {
            const auto & source = *id_to_source.at(existing_id);
            if (!source.hasDependencies(restored_ids))
                return entity;
            LOG_TRACE(log, "{}: Updating dependent", entity->formatTypeWithName());
            auto res = entity->clone();
            res->copyDependenciesFrom(source, restored_ids);
            return res;
        };

        /// It's totally ok if some UUIDs from `ids_to_update` don't exist anymore, that's why we use tryUpdate() here.
        destination_access_storage.tryUpdate(ids_to_update, update_func);
    };

    do_update_dependents(entities_to_restore.dependents);
    do_update_dependents(additional_dependents);
}

}
