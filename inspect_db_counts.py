from sqlalchemy import create_engine, text
engine = create_engine('postgresql://postgres:aaradhiya1@localhost:5432/netfusion')
with engine.connect() as conn:
    print(conn.execute(text('SELECT current_database(), current_user')).fetchall())
    for t in ['cves','iocs','threat_actors','threat_campaigns','mitre_techniques']:
        print(t, conn.execute(text(f'SELECT COUNT(*) FROM {t}')).scalar())
