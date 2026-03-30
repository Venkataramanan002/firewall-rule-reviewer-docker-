from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy import select, func, text
from .models import Connection, Threat, SystemHealth, AdminAudit
import logging

logger = logging.getLogger(__name__)

async def insert_connection(session: AsyncSession, data: dict):
    try:
        conn = Connection(**data)
        session.add(conn)
        await session.commit()
        return conn
    except Exception as e:
        await session.rollback()
        logger.error(f"Error inserting connection: {e}")
        raise

async def insert_threat(session: AsyncSession, data: dict):
    try:
        threat = Threat(**data)
        session.add(threat)
        await session.commit()
        return threat
    except Exception as e:
        await session.rollback()
        logger.error(f"Error inserting threat: {e}")
        raise

async def insert_system_health(session: AsyncSession, data: dict):
    try:
        health = SystemHealth(**data)
        session.add(health)
        await session.commit()
        return health
    except Exception as e:
        await session.rollback()
        logger.error(f"Error inserting system health: {e}")
        raise

async def insert_admin_audit(session: AsyncSession, data: dict):
    try:
        audit = AdminAudit(**data)
        session.add(audit)
        await session.commit()
        return audit
    except Exception as e:
        await session.rollback()
        logger.error(f"Error inserting admin audit: {e}")
        raise

async def data_completeness_report(session: AsyncSession):
    """
    Queries the database and shows % of NULL values per field for connections table.
    """
    fields = [
        "app_name", "app_category", "url", "domain", "user_agent", 
        "http_method", "username", "device_os", "geo_src_country", 
        "geo_dst_country", "nat_src_ip", "decryption_status"
    ]
    
    report = {}
    total_count_result = await session.execute(select(func.count(Connection.id)))
    total_count = total_count_result.scalar() or 0
    
    if total_count == 0:
        return {"total_records": 0, "completeness": "No records found"}
    
    for field in fields:
        null_count_query = text(f"SELECT count(*) FROM connections WHERE {field} IS NULL")
        null_count_result = await session.execute(null_count_query)
        null_count = null_count_result.scalar() or 0
        
        completeness = ((total_count - null_count) / total_count) * 100
        report[field] = f"{completeness:.2f}%"
        
    report["total_records"] = total_count
    return report
