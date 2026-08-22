import pytest

from helpers.cluster import ClickHouseCluster

cluster = ClickHouseCluster(__file__)

node = cluster.add_instance("node", main_configs=["configs/complexity_rules.xml"])
node2 = cluster.add_instance(
    "node2", main_configs=["configs/default_password_type.xml"]
)
node3 = cluster.add_instance(
    "node3", main_configs=["configs/default_password_type_bcrypt.xml"]
)


@pytest.fixture(scope="module")
def start_cluster():
    try:
        cluster.start()
        yield cluster
    finally:
        cluster.shutdown()


def test_complexity_rules(start_cluster):
    error_message = "DB::Exception: Invalid password. The password should: be at least 12 characters long, contain at least 1 numeric character, contain at least 1 lowercase character, contain at least 1 uppercase character, contain at least 1 special character"
    assert error_message in node.query_and_get_error(
        "CREATE USER u_1 IDENTIFIED WITH plaintext_password BY ''"
    )

    error_message = "DB::Exception: Invalid password. The password should: contain at least 1 lowercase character, contain at least 1 uppercase character, contain at least 1 special character"
    assert error_message in node.query_and_get_error(
        "CREATE USER u_2 IDENTIFIED WITH sha256_password BY '000000000000'"
    )

    error_message = "DB::Exception: Invalid password. The password should: contain at least 1 uppercase character, contain at least 1 special character"
    assert error_message in node.query_and_get_error(
        "CREATE USER u_3 IDENTIFIED WITH double_sha1_password BY 'a00000000000'"
    )

    error_message = "DB::Exception: Invalid password. The password should: contain at least 1 special character"
    assert error_message in node.query_and_get_error(
        "CREATE USER u_4 IDENTIFIED WITH plaintext_password BY 'aA0000000000'"
    )

    node.query("CREATE USER u_5 IDENTIFIED WITH plaintext_password BY 'aA!000000000'")
    node.query("DROP USER u_5")


def test_default_password_type(start_cluster):
    node2.query("CREATE USER u1 IDENTIFIED BY 'pwd'")

    required_type = "double_sha1_password"
    assert required_type in node2.query("SHOW CREATE USER u1")


def test_default_sha256_password_is_salted(start_cluster):
    node.query("CREATE USER default_sha256 IDENTIFIED BY 'aA!000000000'")

    definition = node.query(
        "SHOW CREATE USER default_sha256",
        settings={"format_display_secrets_in_show_and_select": 1},
    )
    assert "sha256_hash" in definition
    assert "SALT" in definition


def test_default_bcrypt_password(start_cluster):
    node3.query("CREATE USER default_bcrypt IDENTIFIED BY 'pwd'")

    assert "bcrypt_password" in node3.query("SHOW CREATE USER default_bcrypt")
    assert node3.query("SELECT 1", user="default_bcrypt", password="pwd") == "1\n"
