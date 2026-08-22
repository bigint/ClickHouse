DROP USER IF EXISTS u_05024;

CREATE USER u_05024 GRANTEES CURRENT_USER;
SELECT grantees_any, grantees_list = [currentUser()], grantees_except
FROM system.users
WHERE name = 'u_05024';

ALTER USER u_05024 GRANTEES ANY EXCEPT CURRENT_USER;
SELECT grantees_any, grantees_list, grantees_except = [currentUser()]
FROM system.users
WHERE name = 'u_05024';

DROP USER u_05024;
