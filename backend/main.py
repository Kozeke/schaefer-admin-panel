from fastapi.middleware.cors import CORSMiddleware
from ariadne import make_executable_schema, load_schema_from_path, QueryType, MutationType
from ariadne.asgi import GraphQL
from fastapi import FastAPI
from graphql import GraphQLError
from sqlalchemy import Enum, Column, Integer, String, create_engine, MetaData, Table, DateTime, Float, ForeignKey
from databases import Database
import jwt
import bcrypt
from datetime import datetime, timedelta
from jwt import DecodeError, ExpiredSignatureError
from fastapi import Request
from sqlalchemy import asc, desc, func
from sqlalchemy.sql import select
from datetime import datetime
import random
from faker import Faker

# Database configuration
DATABASE_URL = "postgresql://postgres:postgres@localhost:5432/schaefer-admin"
database = Database(DATABASE_URL)
metadata = MetaData()
JWT_SECRET = "your_jwt_secret_key"
JWT_ALGORITHM = "HS256"


# Define the User table
users_table = Table(
    "users",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String, nullable=False),
    Column("avatar_url", String),
    Column("email", String, unique=True, nullable=False),
    Column("phone", String),
    Column("job_title", String),
    Column("password", String, nullable=False),
    Column("timezone", String, nullable=False),
    Column("role", String, nullable=False),
    Column("created_at", DateTime, nullable=False),
    Column("updated_at", DateTime, nullable=False),
)


events_table = Table(
    "events",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("title", String, nullable=False, key="title"),
    Column("color", String, key="color"),
    Column("start_date", DateTime, nullable=False, key="startDate"),
    Column("end_date", DateTime, nullable=False, key="endDate"),
    Column("description", String, key="description"),
    Column("created_at", DateTime, key="createdAt"),
    Column("updated_at", DateTime, key="updatedAt"),
)

deal_stages_table = Table(
    "deal_stages",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("title", String, nullable=False),
    Column("created_at", DateTime),
    Column("updated_at", DateTime),
)

deals_table = Table(
    "deals",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("title", String, nullable=False),  # Title of the deal
    Column("value", Float, nullable=True),  # Value of the deal
    Column("notes", String, nullable=False),  # Notes for the deal
    Column("close_date", DateTime, nullable=False),  # Close date of the deal
    Column("stage_id", Integer, ForeignKey("deal_stages.id"), nullable=True),  # Deal stage ID
    Column("deal_owner_id", Integer, ForeignKey("users.id"), nullable=False),  # Deal owner ID
    Column("company_id", Integer, ForeignKey("companies.id"), nullable=False),  # Company ID
    Column("created_at", DateTime, nullable=False),  # Creation timestamp
    Column("updated_at", DateTime, nullable=False),  # Last update timestamp
    Column("created_by_id", Integer, ForeignKey("users.id"), nullable=False),  # Created by user ID
    Column("updated_by_id", Integer, ForeignKey("users.id"), nullable=True),  # Updated by user ID
    Column("contact_id", Integer, ForeignKey("contacts.id"), nullable=False),  # Deal contact ID
)

audits_table = Table(
    "audits",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("action", String, nullable=False),
    Column("target_entity", String, nullable=False),
    Column("target_id", String, nullable=False),
    Column("created_at", DateTime, nullable=False, key="createdAt"),
    Column("user_id", Integer, ForeignKey("users.id")),
)

audit_changes_table = Table(
    "audit_changes",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("audit_id", Integer, ForeignKey("audits.id")),
    Column("field", String, nullable=False),
    Column("from_value", String),
    Column("to_value", String),
)

# Define enums for CompanySize, Industry, and BusinessType
COMPANY_SIZE_ENUM = Enum("Small", "Medium", "Large", name="company_size_enum")
INDUSTRY_ENUM = Enum("Technology", "Finance", "Healthcare", name="industry_enum")
BUSINESS_TYPE_ENUM = Enum("B2B", "B2C", name="business_type_enum")

# Define the companies table
companies_table = Table(
    "companies",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String, nullable=False),
    Column("avatar_url", String, nullable=True),
    Column("total_revenue", Integer, nullable=True),
    Column("company_size", COMPANY_SIZE_ENUM, nullable=True),
    Column("industry", INDUSTRY_ENUM, nullable=True),
    Column("business_type", BUSINESS_TYPE_ENUM, nullable=True),
    Column("country", String, nullable=True),
    Column("website", String, nullable=True),
    Column("created_at", DateTime, nullable=False),
    Column("updated_at", DateTime, nullable=False),
    Column("created_by_id", Integer, ForeignKey("users.id"), nullable=False),
    Column("updated_by_id", Integer, ForeignKey("users.id"), nullable=True),
    Column("sales_owner_id", Integer, ForeignKey("users.id"), nullable=False),
)

# Define the contacts table
contacts_table = Table(
    "contacts",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("name", String, nullable=False),
    Column("email", String, nullable=True),
    Column("company_id", Integer, ForeignKey("companies.id"), nullable=True),
)

# Define the company_notes table
company_notes_table = Table(
    "company_notes",
    metadata,
    Column("id", Integer, primary_key=True),
    Column("content", String, nullable=False),
    Column("company_id", Integer, ForeignKey("companies.id"), nullable=True),
)

engine = create_engine(DATABASE_URL)
metadata.create_all(engine)

# Load the SDL schema
type_defs = load_schema_from_path("schema.graphql")

# QueryType resolver
query = QueryType()

# MutationType resolver
mutation = MutationType()

fake = Faker()

@mutation.field("register")
async def resolve_register(_, info, registerInput):
    email = registerInput["email"]
    password = registerInput["password"]

    print(f"Register mutation triggered with email: {email} and password: {password}")

    # Check if the user already exists
    query = users_table.select().where(users_table.c.email == email)
    existing_user = await database.fetch_one(query)
    print(existing_user)
    if existing_user:
        return {"id": None, "email": email, "message": "User already exists!"}

    # Hash the password (use a secure hashing library like bcrypt)
    hashed_password = bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

    # Generate random/default values for other non-nullable fields
    default_name = fake.name()
    default_job_title = fake.job()
    default_timezone = fake.timezone()
    default_role = "User"  # or another default role
    default_avatar_url = f"https://robohash.org/{random.randint(1000, 9999)}.png"  # Placeholder avatar
    default_created_at = fake.date_time_this_year()
    default_updated_at = fake.date_time_this_year()

    # Insert the user into the database and retrieve the ID
    query = users_table.insert().values(
        email=email,
        password=hashed_password,
        name=default_name,
        job_title=default_job_title,
        timezone=default_timezone,
        role=default_role,
        avatar_url=default_avatar_url,
        created_at=default_created_at,
        updated_at=default_updated_at,
    ).returning(users_table.c.id)
    new_user_id = await database.execute(query)
    print(new_user_id)

    # Return the new user
    return {
        "id": new_user_id,
        "email": email,
        "name": default_name,
        "jobTitle": default_job_title,
        "timezone": default_timezone,
        "avatarUrl": default_avatar_url,
    }

@mutation.field("login")
async def resolve_login(_, info, loginInput):
    email = loginInput["email"]
    password = loginInput["password"]
    print(f"Login mutation triggered with email: {email} and password: {password}")
    print(f"Login mutation triggered with email: {email}")

    # Check if the user exists
    query = users_table.select().where(users_table.c.email == email)
    user = await database.fetch_one(query)

    if not user:
        raise ValueError("Invalid email or password")

    # Validate the password
    if not bcrypt.checkpw(password.encode('utf-8'), user["password"].encode('utf-8')):
        raise ValueError("Invalid email or password")

    # Generate a JWT token
    payload = {
        "user_id": user["id"],
        "email": user["email"],
        "exp": datetime.utcnow() + timedelta(hours=24),  # Token expires in 24 hours
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm=JWT_ALGORITHM)

    # Return user info with token
    return {
        "id": user["id"],
        "email": user["email"],
        "accessToken": token,
    }


@query.field("me")
async def resolve_me(_, info):
    # Extract user info from the request context
    request = info.context["request"]
    user_payload = request.state.user

    if not user_payload:
        raise ValueError("Authentication required")

    # Optionally fetch more details from the database
    query = users_table.select().where(users_table.c.id == user_payload["user_id"])
    user = await database.fetch_one(query)

    if not user:
        raise ValueError("User not found")
    print("me no error")
    return {
        "id": user["id"],
        "email": user["email"],
        "name": "Bombieri"
    }

@query.field("user")
async def resolve_user(_, info, id):
    print("resolve user")
    try:
        # Ensure the ID is an integer
        user_id = int(id)
    except ValueError:
        raise ValueError(f"Invalid ID format: {id}. ID must be an integer.")

    # Query the database for the user
    query = select(users_table).where(users_table.c.id == user_id)
    user = await database.fetch_one(query)
    print("user", user)
    if not user:
        raise Exception(f"User with ID {user_id} not found.")

    # Return the user data
    return {
        "id": user["id"],
        "name": user["name"],
        "email": user["email"],
        "phone": user["phone"] if "phone" in user else "",
        "jobTitle": user["job_title"] if "job_title" in user else "",
        "timezone": user["timezone"] if "timezone" in user else "UTC",
        "role": user["role"] if "role" in user else "User",
        "avatarUrl": user["avatar_url"] if "avatar_url" in user else "",
        "createdAt": user["created_at"].isoformat(),
        "updatedAt": user["updated_at"].isoformat(),
    }


@query.field("events")
async def resolve_events(_, info, filter=None, sorting=None, paging=None):
    print("Resolving events")
    query = events_table.select()

    # Apply filters
    if filter:
        print("Applying filters")
        if "startDate" in filter:
            start_date_filter = filter["startDate"]
            if "gte" in start_date_filter:
                query = query.where(
                    events_table.c.startDate >= datetime.fromisoformat(start_date_filter["gte"])
                )
            if "lte" in start_date_filter:
                query = query.where(
                    events_table.c.startDate <= datetime.fromisoformat(start_date_filter["lte"])
                )

        if "title" in filter:
            title_filter = filter["title"]
            if "contains" in title_filter:
                query = query.where(events_table.c.title.ilike(f"%{title_filter['contains']}%"))

    # Apply sorting
    if sorting:
        print("Applying sorting")
        for sort in sorting:
            direction = asc if sort["direction"] == "ASC" else desc
            query = query.order_by(direction(events_table.c[sort["field"]]))

    # Apply pagination
    if paging:
        if "limit" in paging:
            query = query.limit(paging["limit"])
        if "offset" in paging:
            query = query.offset(paging["offset"])

    # Execute query
    results = await database.fetch_all(query)
    print("Results:", results)

    # Count total records for pagination metadata
    total_count_query = select(func.count()).select_from(events_table)
    total_count = await database.execute(total_count_query)

    # Map results to Event objects
    events = [
        {
            "id": row["id"],
            "title": row["title"],
            "color": row["color"],
            "startDate": row["start_date"].isoformat(),  # Convert to ISO format for JSON
            "endDate": row["end_date"].isoformat(),      # Convert to ISO format for JSON
        }
        for row in results
    ]
    print("Events:", events)

    return {
        "totalCount": total_count,
        "nodes": events,
    }

@query.field("dealStages")
async def resolve_deal_stages(_, info, filter=None, sorting=None, paging=None):
    print("Resolving deal stages")
    query = deal_stages_table.select()

    # Apply filters
    if filter:
        if "id" in filter:
            id_filter = filter["id"]
            if "eq" in id_filter:
                query = query.where(deal_stages_table.c.id == id_filter["eq"])
        if "title" in filter:
            title_filter = filter["title"]
            if "contains" in title_filter:
                query = query.where(deal_stages_table.c.title.ilike(f"%{title_filter['contains']}%"))

    # Apply sorting
    if sorting:
        for sort in sorting:
            direction = asc if sort["direction"] == "ASC" else desc
            query = query.order_by(direction(deal_stages_table.c[sort["field"]]))

    # Apply pagination
    if paging:
        if "limit" in paging:
            query = query.limit(paging["limit"])
        if "offset" in paging:
            query = query.offset(paging["offset"])

    # Execute query to get deal stages
    deal_stages = await database.fetch_all(query)
    print("deal stages", deal_stages)
    # Count total records
    total_count_query = select(func.count()).select_from(deal_stages_table)
    total_count = await database.execute(total_count_query)

    # Aggregate deals for each deal stage
    nodes = []
    for stage in deal_stages:
    # Fetch deals aggregate for this stage
        deals_aggregate_query = (
            select(
                func.date_part('month', deals_table.c.close_date).label("closeDateMonth"),
                func.date_part('year', deals_table.c.close_date).label("closeDateYear"),
                func.sum(deals_table.c.value).label("value")
            )
            .where(deals_table.c.stage_id == stage["id"])
            .group_by(
                func.date_part('month', deals_table.c.close_date),
                func.date_part('year', deals_table.c.close_date),
                deals_table.c.close_date 
            )
        )

        deals_aggregate = await database.fetch_all(deals_aggregate_query)
        deals_aggregate = deals_aggregate or []

        # Transform the deals aggregate into the required format
        formatted_aggregate = [
            {
                "groupBy": {
                    "closeDateMonth": int(row["closeDateMonth"]),
                    "closeDateYear": int(row["closeDateYear"]),
                },
                "sum": {
                    "value": float(row["value"] or 0),  # Default to 0 if value is None
                },
            }
            for row in deals_aggregate
        ]

        # Add the stage and its deals aggregate to the nodes list
        nodes.append({
            "id": stage["id"],
            "title": stage["title"],
            "dealsAggregate": formatted_aggregate,
        })


    print("nodess",nodes)
    print("totalCount, deals", total_count)
    return {
        "totalCount": total_count,
        "nodes": nodes,
    }

@query.field("audits")
async def resolve_audits(_, info, filter=None, sorting=None, paging=None):
    print("Resolving audits")
    query = audits_table.select()

    # Apply filters
    if filter:
        if "action" in filter:
            action_filter = filter["action"]
            if "eq" in action_filter:
                query = query.where(audits_table.c.action == action_filter["eq"])
        if "targetEntity" in filter:
            entity_filter = filter["targetEntity"]
            if "contains" in entity_filter:
                query = query.where(audits_table.c.target_entity.ilike(f"%{entity_filter['contains']}%"))
        if "createdAt" in filter:
            created_at_filter = filter["createdAt"]
            if "gte" in created_at_filter:
                query = query.where(audits_table.c.created_at >= datetime.fromisoformat(created_at_filter["gte"]))
            if "lte" in created_at_filter:
                query = query.where(audits_table.c.created_at <= datetime.fromisoformat(created_at_filter["lte"]))

    # Apply sorting
    if sorting:
        print("sort sort")
        for sort in sorting:
            direction = asc if sort["direction"] == "ASC" else desc
            query = query.order_by(direction(audits_table.c[sort["field"]]))

    # Apply pagination
    if paging:
        if "limit" in paging:
            query = query.limit(paging["limit"])
        if "offset" in paging:
            query = query.offset(paging["offset"])

    # Execute query to get audits
    audits = await database.fetch_all(query)
    print("autdits", audits)
    # Count total records
    total_count_query = select(func.count()).select_from(audits_table)
    total_count = await database.execute(total_count_query)

    # Resolve nested fields (changes and user)
    nodes = []
    for audit in audits:
        # Fetch changes for the audit
        changes_query = audit_changes_table.select().where(audit_changes_table.c.audit_id == audit["id"])
        changes = await database.fetch_all(changes_query)
        print("audtis")
        # Fetch user for the audit
        user_query = users_table.select().where(users_table.c.id == audit["user_id"])
        user = await database.fetch_one(user_query)

        nodes.append({
            "id": audit["id"],
            "action": audit["action"],
            "targetEntity": audit["target_entity"],
            "targetId": audit["target_id"],
            "createdAt": audit["created_at"].isoformat(),  # Convert to camelCase
            "user": {
                "id": user["id"] if user else None,
                "name": user["name"] if user else None,
                "avatarUrl": user["avatar_url"] if user else None,
            } if user else None,
            "changes": [
                {
                    "field": change["field"],
                    "from": change["from_value"],
                    "to": change["to_value"],
                }
                for change in changes
            ],
        })
    print("totalCount, audits",total_count)
    return {
        "totalCount": total_count,
        "nodes": nodes,
    }

@query.field("deals")
async def resolve_deals(_, info, filter=None, sorting=None, paging=None):
    # Base query
    total_count_query = select(func.count()).select_from(deals_table)

    query = (
        select(
            deals_table.c.id,
            deals_table.c.title,
            deals_table.c.created_at.label("createdAt"),
            deal_stages_table.c.id.label("stageId"),
            deal_stages_table.c.title.label("stageTitle"),
            companies_table.c.id.label("companyId"),
            companies_table.c.name.label("companyName"),
            companies_table.c.avatar_url.label("companyAvatarUrl"),
        )
        .select_from(
            deals_table
            .join(deal_stages_table, deals_table.c.stage_id == deal_stages_table.c.id)
            .join(companies_table, deals_table.c.company_id == companies_table.c.id)
        )
    )

    # Apply filters
    if filter:
        if "title" in filter:
            title_filter = filter["title"]
            if "contains" in title_filter:
                query = query.where(deals_table.c.title.ilike(f"%{title_filter['contains']}%"))

        if "stageId" in filter:
            query = query.where(deals_table.c.stage_id == filter["stageId"])

        if "companyId" in filter:
            query = query.where(deals_table.c.company_id == filter["companyId"])

    total_count = await database.fetch_val(total_count_query)

    # Apply sorting
    if sorting:
        for sort in sorting:
            direction = asc if sort["direction"] == "ASC" else desc
            query = query.order_by(direction(deals_table.c[sort["field"]]))

    # Apply pagination
    if paging:
        if "limit" in paging:
            query = query.limit(paging["limit"])
        if "offset" in paging:
            query = query.offset(paging["offset"])

    # Execute query and fetch results
    results = await database.fetch_all(query)
    print("resultss", results)


    print("total_count_query", total_count_query)

    # Map results to response format
    nodes = [
        {
            "id": row["id"],
            "title": row["title"],
            "stage": {
                "id": row["stageId"],
                "title": row["stageTitle"],
            },
            "company": {
                "id": row["companyId"],
                "name": row["companyName"],
                "avatarUrl": row["companyAvatarUrl"],
            },
            "createdAt": row["createdAt"].isoformat(),
        }
        for row in results
    ]

    return {
        "totalCount": total_count,
        "nodes": nodes,
    }


@query.field("companies")
async def resolve_companies(_, info, paging=None, filter=None, sorting=None):
    query = companies_table.select()

    # Apply filtering
    if filter:
        if "name" in filter:
            query = query.where(companies_table.c.name.ilike(f"%{filter['name']}%"))

    # Apply sorting
    if sorting:
        for sort in sorting:
            direction = asc if sort["direction"] == "ASC" else desc
            query = query.order_by(direction(companies_table.c[sort["field"]]))

    # Apply pagination
    if paging:
        if "limit" in paging:
            query = query.limit(paging["limit"])
        if "offset" in paging:
            query = query.offset(paging["offset"])

    # Fetch data
    results = await database.fetch_all(query)

    # Fetch total count
    total_count_query = select(func.count()).select_from(companies_table)
    total_count = await database.fetch_val(total_count_query)

    return {
        "totalCount": total_count,
        "nodes": [dict(result) for result in results],
    }


@query.field("contact")
async def resolve_contact(_, info, id):
    query = contacts_table.select().where(contacts_table.c.id == id)
    contact = await database.fetch_one(query)
    if not contact:
        raise Exception(f"Contact with ID {id} not found")
    return dict(contact)


@query.field("contacts")
async def resolve_contacts(_, info, paging=None, filter=None, sorting=None):
    query = contacts_table.select()

    # Apply filtering
    if filter:
        if "name" in filter:
            query = query.where(contacts_table.c.name.ilike(f"%{filter['name']}%"))

    # Apply sorting
    if sorting:
        for sort in sorting:
            direction = asc if sort["direction"] == "ASC" else desc
            query = query.order_by(direction(contacts_table.c[sort["field"]]))

    # Apply pagination
    if paging:
        if "limit" in paging:
            query = query.limit(paging["limit"])
        if "offset" in paging:
            query = query.offset(paging["offset"])

    # Fetch data
    results = await database.fetch_all(query)

    # Fetch total count
    total_count_query = select(func.count()).select_from(contacts_table)
    total_count = await database.fetch_val(total_count_query)

    return {
        "totalCount": total_count,
        "nodes": [dict(result) for result in results],
    }


# Create executable schema
schema = make_executable_schema(type_defs, query, mutation)

# FastAPI app
app = FastAPI()

# Add CORS middleware
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],  # Add the URL of your frontend
    allow_credentials=True,
    allow_methods=["*"],  # Allow all HTTP methods
    allow_headers=["*"],  # Allow all headers
)

@app.middleware("http")
async def authenticate_request(request: Request, call_next):
    auth_header = request.headers.get("Authorization")
    if auth_header:
        try:
            token = auth_header.split(" ")[1]
            payload = jwt.decode(token, JWT_SECRET, algorithms=[JWT_ALGORITHM])
            request.state.user = payload  # Attach user info to the request
        except (DecodeError, ExpiredSignatureError):
            request.state.user = None
    else:
        request.state.user = None
    return await call_next(request)

@app.on_event("startup")
async def startup():
    await database.connect()

@app.on_event("shutdown")
async def shutdown():
    await database.disconnect()

# Mount GraphQL endpoint
graphql_app = GraphQL(schema)
app.mount("/graphql", graphql_app)
