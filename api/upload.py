import io
import logging
from fastapi import APIRouter, UploadFile, File, Depends, HTTPException, Query
from fastapi.responses import StreamingResponse
from sqlalchemy.ext.asyncio import AsyncSession

from sqlalchemy import delete as sql_delete
from database.connection import get_db
from database.models import Connection, Threat, FirewallRule, NetworkTopology, SystemHealth
from services.data_importer import ingest_data_file, validate_upload_file
from utils.template_generator import generate_template

logger = logging.getLogger(__name__)
router = APIRouter()

ALLOWED_EXTENSIONS = ['.csv', '.json', '.xlsx', '.xls']


@router.post('/api/upload-data')
async def upload_data(file: UploadFile = File(...), clear_data: bool = Query(False), db: AsyncSession = Depends(get_db)):
    try:
        if not file.filename:
            raise HTTPException(status_code=400, detail='Filename is required')

        if not any(file.filename.lower().endswith(ext) for ext in ALLOWED_EXTENSIONS):
            raise HTTPException(
                status_code=400,
                detail=f'Allowed extensions are {", ".join(ALLOWED_EXTENSIONS)}. '
                       f'For firewall configs (.xml, .conf), use the config upload endpoint.'
            )

        # Clear previous traffic/threat data before ingesting new upload
        if clear_data:
            try:
                await db.execute(sql_delete(SystemHealth))
                await db.execute(sql_delete(Threat))
                await db.execute(sql_delete(Connection))
                await db.commit()
            except Exception:
                await db.rollback()

        # Use the proper data importer which handles CSV, JSON, and Excel
        result = await ingest_data_file(file, db)

        return {
            "message": "Data ingested successfully",
            "file_type": result.get("file_type"),
            "total_rows": result.get("total_rows", 0),
            "processed_rows": result.get("processed_rows", 0),
            "errors_count": result.get("errors_count", 0),
            "warnings_count": result.get("warnings_count", 0),
            "inserted_counts": result.get("inserted_counts", {}),
            "errors": result.get("errors", [])[:20],  # Limit error details in response
        }
    except ValueError as ve:
        logger.error('Upload data validation error: %s', ve)
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as e:
        logger.exception('Unhandled exception in upload_data: %s', e)
        raise HTTPException(status_code=500, detail=f'Data ingestion failed: {str(e)}')


@router.post('/api/validate-upload')
async def validate_upload(file: UploadFile = File(...)):
    try:
        if not file.filename:
            raise HTTPException(status_code=400, detail='Filename is required')

        if not any(file.filename.lower().endswith(ext) for ext in ['.csv', '.json', '.xlsx', '.xls']):
            raise HTTPException(status_code=400, detail='Allowed extensions are .csv, .json, .xlsx')

        result = await validate_upload_file(file)
        return result
    except ValueError as ve:
        logger.error('Validate upload failed: %s', ve)
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as exc:
        logger.exception('Validate upload exception: %s', exc)
        raise HTTPException(status_code=500, detail='Validation failed')


@router.get('/api/download-template')
async def download_template(format: str = Query('csv', pattern='^(csv|json|excel)$')):
    try:
        content, mime_type, filename = generate_template(format)
        return StreamingResponse(io.BytesIO(content), media_type=mime_type, headers={
            'Content-Disposition': f'attachment; filename="{filename}"'
        })
    except ValueError as ve:
        logger.error('Download template failed: %s', ve)
        raise HTTPException(status_code=400, detail=str(ve))
    except Exception as exc:
        logger.exception('Download template error: %s', exc)
        raise HTTPException(status_code=500, detail='Could not generate template')
