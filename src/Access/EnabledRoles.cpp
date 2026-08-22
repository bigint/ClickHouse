#include <Access/EnabledRoles.h>
#include <Access/EnabledRolesInfo.h>
#include <Access/Role.h>
#include <boost/range/algorithm/copy.hpp>
#include <Common/Exception.h>


namespace DB
{
EnabledRoles::EnabledRoles(const Params & params_) : params(params_), handlers(std::make_shared<Handlers>())
{
}

EnabledRoles::~EnabledRoles() = default;


std::shared_ptr<const EnabledRolesInfo> EnabledRoles::getRolesInfo() const
{
    std::lock_guard lock{info_mutex};
    return info;
}


scope_guard EnabledRoles::subscribeForChanges(const OnChangeHandler & handler) const
{
    auto entry = std::make_shared<Handler>(handler);
    std::lock_guard lock{handlers->mutex};
    handlers->list.push_back(entry);
    auto it = std::prev(handlers->list.end());

    return [my_handlers = handlers, entry, it]
    {
        std::lock_guard delivery_lock{entry->mutex};
        entry->active = false;
        std::lock_guard lock2{my_handlers->mutex};
        my_handlers->list.erase(it);
    };
}


void EnabledRoles::setRolesInfo(const std::shared_ptr<const EnabledRolesInfo> & info_, scope_guard * notifications)
{
    {
        std::lock_guard lock{info_mutex};
        if (info && info_ && *info == *info_)
            return;

        info = info_;
    }

    if (notifications)
    {
        std::vector<std::shared_ptr<Handler>> handlers_to_notify;
        {
            std::lock_guard lock{handlers->mutex};
            boost::range::copy(handlers->list, std::back_inserter(handlers_to_notify));
        }

        /// Copy the value published by this update while it is still unambiguous. Reading
        /// `info` here after releasing `info_mutex` would race with another recalculation,
        /// and could also deliver that later recalculation's value for this notification.
        notifications->join(scope_guard(
            [my_info = info_, my_handlers_to_notify = std::move(handlers_to_notify)]
            {
                for (const auto & entry : my_handlers_to_notify)
                {
                    std::lock_guard delivery_lock{entry->mutex};
                    if (entry->active)
                    {
                        try
                        {
                            entry->function(my_info);
                        }
                        catch (...)
                        {
                            tryLogCurrentException(__PRETTY_FUNCTION__);
                        }
                    }
                }
            }));
    }
}

}
