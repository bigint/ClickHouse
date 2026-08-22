#include <Access/AccessEntityIO.h>
#include <Access/IAccessEntity.h>
#include <Access/IAccessStorage.h>
#include <Access/MaskingPolicy.h>
#include <Access/Quota.h>
#include <Access/Role.h>
#include <Access/RowPolicy.h>
#include <Access/SettingsProfile.h>
#include <Access/User.h>
#include <Core/Defines.h>
#include <IO/WriteHelpers.h>
#include <Interpreters/Access/InterpreterCreateQuotaQuery.h>
#include <Interpreters/Access/InterpreterCreateRoleQuery.h>
#include <Interpreters/Access/InterpreterCreateRowPolicyQuery.h>
#include <Interpreters/Access/InterpreterCreateSettingsProfileQuery.h>
#include <Interpreters/Access/InterpreterCreateUserQuery.h>
#include <Interpreters/Access/InterpreterGrantQuery.h>
#include <Interpreters/Access/InterpreterShowCreateAccessEntityQuery.h>
#include <Interpreters/Access/InterpreterShowGrantsQuery.h>
#include <Parsers/Access/ASTCreateQuotaQuery.h>
#include <Parsers/Access/ASTCreateRoleQuery.h>
#include <Parsers/Access/ASTCreateRowPolicyQuery.h>
#include <Parsers/Access/ASTCreateMaskingPolicyQuery.h>
#include <Parsers/Access/ASTCreateSettingsProfileQuery.h>
#include <Parsers/Access/ASTCreateUserQuery.h>
#include <Parsers/Access/ASTGrantQuery.h>
#include <Parsers/ParserAttachAccessEntity.h>
#include <Parsers/parseQuery.h>
#include <boost/range/algorithm_ext/push_back.hpp>

namespace DB
{
namespace ErrorCodes
{
    extern const int INCORRECT_ACCESS_ENTITY_DEFINITION;
}

String serializeAccessEntity(const IAccessEntity & entity)
{
    /// Build list of ATTACH queries.
    ASTs queries;
    queries.push_back(InterpreterShowCreateAccessEntityQuery::getAttachQuery(entity));
    if ((entity.getType() == AccessEntityType::USER) || (entity.getType() == AccessEntityType::ROLE))
        boost::range::push_back(queries, InterpreterShowGrantsQuery::getAttachGrantQueries(entity));

    /// Serialize the list of ATTACH queries to a string.
    WriteBufferFromOwnString buf;
    IAST::FormatSettings format_settings(/*one_line=*/true);
    for (const ASTPtr & query : queries)
    {
        query->format(buf, format_settings);
        buf.write(";\n", 2);
    }
    return buf.str();
}

static AccessEntityPtr deserializeAccessEntityImpl(const String & definition)
{
    ASTs queries;
    ParserAttachAccessEntity parser;
    const char * begin = definition.data(); /// begin of current query
    const char * pos = begin; /// parser moves pos from begin to the end of current query
    const char * end = begin + definition.size();
    while (pos < end)
    {
        queries.emplace_back(parseQueryAndMovePosition(parser, pos, end, "", true, 0, DBMS_DEFAULT_MAX_PARSER_DEPTH, DBMS_DEFAULT_MAX_PARSER_BACKTRACKS));
        while (isWhitespaceASCII(*pos) || *pos == ';')
            ++pos;
    }

    /// Interpret the AST to build an access entity.
    std::shared_ptr<User> user;
    std::shared_ptr<Role> role;
    std::shared_ptr<RowPolicy> policy;
    std::shared_ptr<MaskingPolicy> masking_policy;
    std::shared_ptr<Quota> quota;
    std::shared_ptr<SettingsProfile> profile;
    AccessEntityPtr res;

    for (const auto & query : queries)
    {
        if (auto * create_user_query = query->as<ASTCreateUserQuery>())
        {
            if (res)
                throw Exception(ErrorCodes::INCORRECT_ACCESS_ENTITY_DEFINITION, "Two access entities attached in the same file");
            res = user = std::make_unique<User>();
            InterpreterCreateUserQuery::updateUserFromQuery(*user, *create_user_query, /* allow_no_password = */ true, /* allow_plaintext_password = */ true, /* max_number_of_authentication_methods = zero is unlimited*/ 0);
        }
        else if (auto * create_role_query = query->as<ASTCreateRoleQuery>())
        {
            if (res)
                throw Exception(ErrorCodes::INCORRECT_ACCESS_ENTITY_DEFINITION, "Two access entities attached in the same file");
            res = role = std::make_unique<Role>();
            InterpreterCreateRoleQuery::updateRoleFromQuery(*role, *create_role_query);
        }
        else if (auto * create_policy_query = query->as<ASTCreateRowPolicyQuery>())
        {
            if (res)
                throw Exception(ErrorCodes::INCORRECT_ACCESS_ENTITY_DEFINITION, "Two access entities attached in the same file");
            res = policy = std::make_unique<RowPolicy>();
            InterpreterCreateRowPolicyQuery::updateRowPolicyFromQuery(*policy, *create_policy_query);
        }
        else if (auto * create_masking_policy_query = query->as<ASTCreateMaskingPolicyQuery>())
        {
            if (res)
                throw Exception(ErrorCodes::INCORRECT_ACCESS_ENTITY_DEFINITION, "Two access entities attached in the same file");
            res = masking_policy = std::make_unique<MaskingPolicy>();
            masking_policy->setFullName(
                create_masking_policy_query->name,
                create_masking_policy_query->database,
                create_masking_policy_query->table_name);
            if (create_masking_policy_query->update_assignments)
                masking_policy->update_assignments = create_masking_policy_query->update_assignments->clone();
            if (create_masking_policy_query->where_condition)
                masking_policy->where_condition = create_masking_policy_query->where_condition->clone();
            masking_policy->priority = create_masking_policy_query->priority;
            if (create_masking_policy_query->roles)
                masking_policy->to_roles = *create_masking_policy_query->roles;
        }
        else if (auto * create_quota_query = query->as<ASTCreateQuotaQuery>())
        {
            if (res)
                throw Exception(ErrorCodes::INCORRECT_ACCESS_ENTITY_DEFINITION, "Two access entities attached in the same file");
            res = quota = std::make_unique<Quota>();
            InterpreterCreateQuotaQuery::updateQuotaFromQuery(*quota, *create_quota_query);
        }
        else if (auto * create_profile_query = query->as<ASTCreateSettingsProfileQuery>())
        {
            if (res)
                throw Exception(ErrorCodes::INCORRECT_ACCESS_ENTITY_DEFINITION, "Two access entities attached in the same file");
            res = profile = std::make_unique<SettingsProfile>();
            InterpreterCreateSettingsProfileQuery::updateSettingsProfileFromQuery(*profile, *create_profile_query);
        }
        else if (auto * grant_query = query->as<ASTGrantQuery>())
        {
            if (!user && !role)
                throw Exception(ErrorCodes::INCORRECT_ACCESS_ENTITY_DEFINITION, "A user or role should be attached before grant");
            if (user)
                InterpreterGrantQuery::updateUserFromQuery(*user, *grant_query);
            else
                InterpreterGrantQuery::updateRoleFromQuery(*role, *grant_query);
        }
        else
            throw Exception(ErrorCodes::INCORRECT_ACCESS_ENTITY_DEFINITION, "No interpreter found for query {}", query->getID());
    }

    if (!res)
        throw Exception(ErrorCodes::INCORRECT_ACCESS_ENTITY_DEFINITION, "No access entities attached");

    return res;
}


AccessEntityPtr deserializeAccessEntity(const String & definition, const String & file_path)
{
    if (file_path.empty())
        return deserializeAccessEntityImpl(definition);

    try
    {
        return deserializeAccessEntityImpl(definition);
    }
    catch (Exception & e)
    {
        e.addMessage("Could not parse " + file_path);
        throw;
    }
}

}
