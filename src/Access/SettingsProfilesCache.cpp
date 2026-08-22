#include <Access/SettingsProfilesCache.h>
#include <Access/AccessControl.h>
#include <Access/SettingsProfile.h>
#include <Access/SettingsProfilesInfo.h>
#include <Common/Logger.h>
#include <Common/ProfileEvents.h>
#include <Common/Stopwatch.h>
#include <Common/logger_useful.h>
#include <Common/quoteString.h>

#include <unordered_set>


namespace ProfileEvents
{
    /// NOLINT: not settings; the names contain "Settings" so check-settings-style mistakes them for setting externs.
    extern const Event SettingsProfileCacheRecalculations; // NOLINT
    extern const Event SettingsProfileCacheRecalculationMicroseconds; // NOLINT
}

namespace DB
{
namespace ErrorCodes
{
    extern const int THERE_IS_NO_PROFILE;
}

SettingsProfilesCache::SettingsProfilesCache(const AccessControl & access_control_)
    : access_control(access_control_) {}

SettingsProfilesCache::~SettingsProfilesCache()
{
    subscription.reset();
}


void SettingsProfilesCache::ensureAllProfilesRead()
{
    /// `mutex` is already locked.
    if (all_profiles_read)
        return;

    /// An earlier initial scan can have thrown after establishing the subscription.
    /// Reuse it on retry: replacing it while holding `mutex` can deadlock with the old
    /// handler, whose unsubscription waits for delivery while that delivery waits here.
    if (!subscription)
    {
        subscription = access_control.subscribeForAllChanges(
            [this](const std::vector<AccessChangesNotifier::Change> & changes)
            {
                std::lock_guard lock{mutex};
                std::unordered_set<UUID> changed_ids;
                for (const auto & change : changes)
                    changed_ids.emplace(change.id);

                auto new_all_profiles = all_profiles;
                bool profiles_changed = false;
                for (const auto & id : changed_ids)
                {
                    auto entity = access_control.tryRead(id);
                    if (auto profile = entity ? typeid_cast<SettingsProfilePtr>(entity) : nullptr)
                    {
                        auto [it, inserted] = new_all_profiles.emplace(id, profile);
                        if (!inserted && it->second != profile)
                        {
                            it->second = profile;
                            profiles_changed = true;
                        }
                        profiles_changed |= inserted;
                    }
                    else
                        profiles_changed |= new_all_profiles.erase(id) != 0;
                }

                if (!profiles_changed)
                    return;

                std::optional<UUID> new_default_profile_id;
                if (!default_profile_name.empty())
                    new_default_profile_id = access_control.find<SettingsProfile>(default_profile_name);

                const auto old_default_profile_id = default_profile_id;
                const bool old_need_merge_settings_and_constraints = need_merge_settings_and_constraints;
                all_profiles.swap(new_all_profiles);
                default_profile_id = new_default_profile_id;
                scope_guard rollback = [&]
                {
                    all_profiles.swap(new_all_profiles);
                    default_profile_id = old_default_profile_id;
                    profile_infos_cache.clear();
                    need_merge_settings_and_constraints = old_need_merge_settings_and_constraints;
                };
                profile_infos_cache.clear();
                need_merge_settings_and_constraints = true;
                mergeSettingsAndConstraintsIfNeeded();
                rollback.release();
            });
    }

    /// Start clean: a previous attempt may have thrown mid-scan.
    all_profiles.clear();
    for (const UUID & id : access_control.findAll<SettingsProfile>())
    {
        auto profile = access_control.tryRead<SettingsProfile>(id);
        if (profile)
            all_profiles.emplace(id, profile);
    }

    /// Set only after the subscription and the initial read succeed.
    all_profiles_read = true;
}


void SettingsProfilesCache::setDefaultProfileName(const String & default_profile_name)
{
    std::lock_guard lock{mutex};
    ensureAllProfilesRead();

    std::optional<UUID> new_default_profile_id;
    if (default_profile_name.empty())
    {
        new_default_profile_id = {};
    }
    else
    {
        new_default_profile_id = access_control.find<SettingsProfile>(default_profile_name);
        if (!new_default_profile_id)
            throw Exception(ErrorCodes::THERE_IS_NO_PROFILE, "Settings profile {} not found", backQuote(default_profile_name));
    }

    if ((this->default_profile_name == default_profile_name) && (default_profile_id == new_default_profile_id))
        return;

    const String old_default_profile_name = this->default_profile_name;
    const auto old_default_profile_id = default_profile_id;
    const bool old_need_merge_settings_and_constraints = need_merge_settings_and_constraints;
    scope_guard rollback = [&]
    {
        this->default_profile_name = old_default_profile_name;
        default_profile_id = old_default_profile_id;
        need_merge_settings_and_constraints = old_need_merge_settings_and_constraints;
    };

    this->default_profile_name = default_profile_name;
    default_profile_id = new_default_profile_id;
    need_merge_settings_and_constraints = true;
    mergeSettingsAndConstraintsIfNeeded();
    rollback.release();
}


void SettingsProfilesCache::mergeSettingsAndConstraintsIfNeeded()
{
    /// `mutex` is already locked.
    if (!need_merge_settings_and_constraints)
        return;
    /// Clear the flag only after a successful rebuild, so a throwing recompute is retried next batch.
    mergeSettingsAndConstraints();
    need_merge_settings_and_constraints = false;
}


void SettingsProfilesCache::mergeSettingsAndConstraints()
{
    /// `mutex` is already locked.
    ProfileEvents::increment(ProfileEvents::SettingsProfileCacheRecalculations);
    Stopwatch watch;
    std::vector<std::pair<std::shared_ptr<EnabledSettings>, std::shared_ptr<const SettingsProfilesInfo>>> recalculated;
    recalculated.reserve(enabled_settings.size());
    for (auto i = enabled_settings.begin(), e = enabled_settings.end(); i != e;)
    {
        auto enabled = i->second.lock();
        if (!enabled)
            i = enabled_settings.erase(i);
        else
        {
            recalculated.emplace_back(enabled, calculateSettingsAndConstraintsFor(*enabled));
            ++i;
        }
    }

    for (const auto & [enabled, info] : recalculated)
        enabled->setInfo(info);

    const auto elapsed_ms = watch.elapsedMilliseconds();
    ProfileEvents::increment(ProfileEvents::SettingsProfileCacheRecalculationMicroseconds, watch.elapsedMicroseconds());
    /// O(enabled sets * profiles), under `mutex` that the ContextAccess build path also takes.
    if (elapsed_ms >= 1000)
        LOG_DEBUG(getLogger("SettingsProfilesCache"), "Re-merged settings and constraints for {} enabled set(s) over {} profiles in {} ms", enabled_settings.size(), all_profiles.size(), elapsed_ms);
    else
        LOG_TRACE(getLogger("SettingsProfilesCache"), "Re-merged settings and constraints for {} enabled set(s) over {} profiles in {} ms", enabled_settings.size(), all_profiles.size(), elapsed_ms);
}


std::shared_ptr<const SettingsProfilesInfo> SettingsProfilesCache::calculateSettingsAndConstraintsFor(const EnabledSettings & enabled) const
{
    SettingsProfileElements merged_settings;
    if (default_profile_id)
    {
        SettingsProfileElement new_element;
        new_element.parent_profile = *default_profile_id;
        merged_settings.emplace_back(new_element);
    }

    for (const auto & [profile_id, profile] : all_profiles)
        if (profile->to_roles.match(enabled.params.user_id, enabled.params.enabled_roles))
        {
            SettingsProfileElement new_element;
            new_element.parent_profile = profile_id;
            merged_settings.emplace_back(new_element);
        }

    merged_settings.merge(enabled.params.settings_from_enabled_roles, /* normalize= */ false);
    merged_settings.merge(enabled.params.settings_from_user, /* normalize= */ false);

    auto info = std::make_shared<SettingsProfilesInfo>(access_control);

    substituteProfiles(merged_settings, info->profiles, info->profiles_with_implicit, info->names_of_profiles);

    info->settings = merged_settings.toSettingsChanges();
    info->constraints = merged_settings.toSettingsConstraints(access_control);

    return info;
}


void SettingsProfilesCache::substituteProfiles(
    SettingsProfileElements & elements,
    std::vector<UUID> & profiles,
    std::vector<UUID> & substituted_profiles,
    std::unordered_map<UUID, String> & names_of_substituted_profiles) const
{
    profiles = elements.toProfileIDs();

    /// We should substitute profiles in reversive order because the same profile can occur
    /// in `elements` multiple times (with some other settings in between) and in this case
    /// the last occurrence should override all the previous ones.
    boost::container::flat_set<UUID> substituted_profiles_set;
    size_t i = elements.size();
    while (i != 0)
    {
        auto & element = elements[--i];
        if (!element.parent_profile)
            continue;

        auto profile_id = *element.parent_profile;
        element.parent_profile.reset();
        if (substituted_profiles_set.count(profile_id))
            continue;

        auto profile_it = all_profiles.find(profile_id);
        if (profile_it == all_profiles.end())
            continue;

        const auto & profile = profile_it->second;
        const auto & profile_elements = profile->elements;
        elements.insert(elements.begin() + i, profile_elements.begin(), profile_elements.end());
        i += profile_elements.size();
        substituted_profiles.push_back(profile_id);
        substituted_profiles_set.insert(profile_id);
        names_of_substituted_profiles.emplace(profile_id, profile->getName());
    }
    std::reverse(substituted_profiles.begin(), substituted_profiles.end());

    std::erase_if(profiles, [&substituted_profiles_set](const UUID & profile_id)
    {
        return !substituted_profiles_set.contains(profile_id);
    });
}

std::shared_ptr<const EnabledSettings> SettingsProfilesCache::getEnabledSettings(
    const UUID & user_id,
    const SettingsProfileElements & settings_from_user,
    const boost::container::flat_set<UUID> & enabled_roles,
    const SettingsProfileElements & settings_from_enabled_roles)
{
    std::lock_guard lock{mutex};
    ensureAllProfilesRead();

    EnabledSettings::Params params;
    params.user_id = user_id;
    params.settings_from_user = settings_from_user;
    params.enabled_roles = enabled_roles;
    params.settings_from_enabled_roles = settings_from_enabled_roles;

    auto it = enabled_settings.find(params);
    if (it != enabled_settings.end())
    {
        auto from_cache = it->second.lock();
        if (from_cache)
            return from_cache;
        enabled_settings.erase(it);
    }

    std::shared_ptr<EnabledSettings> res(new EnabledSettings(params));
    enabled_settings.emplace(std::move(params), res);
    res->setInfo(calculateSettingsAndConstraintsFor(*res));
    return res;
}


std::shared_ptr<const SettingsProfilesInfo> SettingsProfilesCache::getSettingsProfileInfo(const UUID & profile_id)
{
    std::lock_guard lock{mutex};
    ensureAllProfilesRead();

    if (auto pos = this->profile_infos_cache.get(profile_id))
        return *pos;

    SettingsProfileElements elements;
    auto & element = elements.emplace_back();
    element.parent_profile = profile_id;

    auto info = std::make_shared<SettingsProfilesInfo>(access_control);

    substituteProfiles(elements, info->profiles, info->profiles_with_implicit, info->names_of_profiles);
    info->settings = elements.toSettingsChanges();
    info->constraints.merge(elements.toSettingsConstraints(access_control));

    profile_infos_cache.add(profile_id, info);
    return info;
}

}
