import sqlite3

SCHEMA = """
create table members (id integer primary key, email text unique, name text, dob text, role text default 'member', password_md5 text);
create table records (id integer primary key, member_id integer, kind text, note text);
create table messages (id integer primary key, member_id integer, body text);
"""


def connect(path=":memory:"):
    con = sqlite3.connect(path, check_same_thread=False)
    con.row_factory = sqlite3.Row
    return con


def seed(con):
    import hashlib

    con.executescript(SCHEMA)
    people = [
        (1, "ada@example.test", "Ada Rowan", "1984-02-11", "member", "pw-ada"),
        (2, "ben@example.test", "Ben Ortiz", "1979-07-30", "member", "pw-ben"),
        (3, "cora@example.test", "Cora Lind", "1991-11-02", "member", "pw-cora"),
        (9, "admin@example.test", "Care Admin", "1980-01-01", "admin", "pw-admin"),
    ]
    for pid, email, name, dob, role, pw in people:
        con.execute("insert into members values (?,?,?,?,?,?)", (pid, email, name, dob, role, hashlib.md5(pw.encode()).hexdigest()))
    con.execute("insert into records (member_id, kind, note) values (1,'diagnosis','IBS-D, flare in March')")
    con.execute("insert into records (member_id, kind, note) values (2,'diagnosis','Crohn disease, on biologic')")
    con.execute("insert into records (member_id, kind, note) values (3,'lab','Calprotectin elevated')")
    con.execute("insert into messages (member_id, body) values (2, 'Please refill my prescription')")
    con.commit()
