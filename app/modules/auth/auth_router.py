import json
import logging
import os
from datetime import datetime, timezone

import requests
from dotenv import load_dotenv
from fastapi import Depends, Request
from fastapi.responses import JSONResponse, Response
from fastapi.exceptions import HTTPException
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials

from sqlalchemy.orm import Session

logger = logging.getLogger(__name__)

from app.core.database import get_db
from app.modules.auth.auth_schema import (
    LoginRequest,
    SSOLoginRequest,
    ConfirmLinkingRequest,
    UnlinkProviderRequest,
    SetPrimaryProviderRequest,
    UserAuthProvidersResponse,
    AuthProviderResponse,
    AccountResponse,
    AuthProviderCreate,
)
from app.modules.auth.auth_service import auth_handler
from app.modules.auth.unified_auth_service import UnifiedAuthService
from app.modules.users.user_schema import CreateUser
from app.modules.users.user_service import UserService
from app.modules.utils.APIRouter import APIRouter
from app.modules.utils.posthog_helper import PostHogClient

SLACK_WEBHOOK_URL = os.getenv("SLACK_WEBHOOK_URL", None)

auth_router = APIRouter()
load_dotenv(override=True)


async def send_slack_message(message: str):
    payload = {"text": message}
    if SLACK_WEBHOOK_URL:
        requests.post(SLACK_WEBHOOK_URL, json=payload)


class AuthAPI:
    @auth_router.post("/login")
    async def login(login_request: LoginRequest):
        email, password = login_request.email, login_request.password

        try:
            res = auth_handler.login(email=email, password=password)
            id_token = res.get("idToken")
            return JSONResponse(content={"token": id_token}, status_code=200)
        except ValueError:
            return JSONResponse(
                content={"error": "Invalid email or password"}, status_code=401
            )
        except HTTPException as he:
            return JSONResponse(
                content={"error": f"HTTP Error: {str(he)}"}, status_code=he.status_code
            )
        except Exception as e:
            return JSONResponse(content={"error": f"ERROR: {str(e)}"}, status_code=400)

    @auth_router.post("/signup")
    async def signup(request: Request, db: Session = Depends(get_db)):
        try:
            body = json.loads(await request.body())
            uid = body.get("uid")
            if not uid:
                return Response(
                    content=json.dumps({"error": "uid is required"}), status_code=400
                )

            email = body.get("email")
            if not email:
                return Response(
                    content=json.dumps({"error": "email is required"}), status_code=400
                )

            # These fields are optional (only present for GitHub OAuth signup)
            oauth_token = body.get("accessToken", "")
            provider_data = body.get("providerData", [])
            provider_username = body.get("providerUsername", "")

            user_service = UserService(db)
            user = user_service.get_user_by_uid(uid)

            # Also check by email in case user exists with different UID (e.g., SSO signup)
            user_by_email = user_service.get_user_by_email(email)

            # If user exists by email but not by UID, we need to link accounts
            if user_by_email and user_by_email.uid != uid:
                logger.info(
                    f"Email {email} exists with different UID. Linking accounts: {user_by_email.uid} -> {uid}"
                )
                existing_uid = user_by_email.uid

                # Update the existing user's UID to match the new Firebase UID
                # This links the SSO account with the email/password account
                try:
                    # Update user UID in database
                    user_by_email.uid = uid
                    db.commit()
                    logger.info(
                        f"Updated user UID from {existing_uid} to {uid} for email {email}"
                    )

                    # Add email/password provider to the unified auth system
                    unified_auth = UnifiedAuthService(db)
                    provider_create = AuthProviderCreate(
                        provider_type="firebase_email",
                        provider_uid=uid,
                        provider_data={"email": email, "uid": uid},
                        access_token=None,
                        is_primary=False,  # Keep SSO as primary if it exists
                    )
                    unified_auth.add_provider(uid, provider_create)
                    logger.info(f"Added firebase_email provider for user {uid}")

                    return Response(
                        content=json.dumps(
                            {"uid": uid, "exists": True, "linked": True}
                        ),
                        status_code=200,
                    )
                except Exception as e:
                    logger.error(f"Error linking accounts: {str(e)}")
                    import traceback

                    logger.error(f"Traceback: {traceback.format_exc()}")
                    db.rollback()
                    return Response(
                        content=json.dumps(
                            {"error": f"Failed to link accounts: {str(e)}"}
                        ),
                        status_code=400,
                    )

            if user:
                # Existing user - DO NOT update email if it's different (preserve primary sign-in email)
                # When GitHub is linked, Firebase might send GitHub email, but we keep the original email
                if email and email.lower() != user.email.lower():
                    logger.info(
                        f"Email mismatch: GitHub email {email} vs existing user email {user.email}. Keeping existing email {user.email}."
                    )
                    # Don't update the email - keep the primary sign-in email

                # Existing user - update last login
                if oauth_token:
                    message, error = user_service.update_last_login(uid, oauth_token)
                    if error:
                        return Response(content=message, status_code=400)

                # Also add GitHub as a provider in the new system if it's a GitHub signup
                if oauth_token and provider_data and len(provider_data) > 0:
                    try:
                        unified_auth = UnifiedAuthService(db)
                        provider_info = (
                            provider_data[0]
                            if isinstance(provider_data, list)
                            else provider_data
                        )

                        # Check if GitHub provider already exists
                        existing_github = unified_auth.get_provider(
                            uid, "firebase_github"
                        )
                        if not existing_github:
                            # Add GitHub as a provider
                            provider_create = AuthProviderCreate(
                                provider_type="firebase_github",
                                provider_uid=provider_username or uid,
                                provider_data=provider_info,
                                access_token=oauth_token,
                                is_primary=False,  # Don't make it primary automatically for existing users
                            )
                            unified_auth.add_provider(uid, provider_create)
                            logger.info(
                                f"Linked GitHub provider to existing user {uid}"
                            )
                        else:
                            # User already has GitHub provider
                            # Check if user has other providers - if yes, this is likely a link operation, not a sign-in
                            # Only set GitHub as primary if it's the only provider (user signed up with GitHub)
                            all_providers = unified_auth.get_user_providers(uid)
                            has_other_providers = any(
                                p.provider_type != "firebase_github"
                                for p in all_providers
                            )

                            if (
                                not existing_github.is_primary
                                and not has_other_providers
                            ):
                                # User only has GitHub - this is a GitHub sign-in, set as primary
                                logger.info(
                                    f"User {uid} signed in with GitHub (only provider) - setting GitHub as primary provider"
                                )
                                unified_auth.set_primary_provider(
                                    uid, "firebase_github"
                                )
                            elif not existing_github.is_primary and has_other_providers:
                                # User has other providers - this is a link operation, don't change primary
                                logger.info(
                                    f"User {uid} linking GitHub (has other providers) - keeping existing primary provider"
                                )
                            # Update last used
                            unified_auth.update_last_used(uid, "firebase_github")
                    except Exception as e:
                        logger.warning(
                            f"Failed to add GitHub provider for existing user: {str(e)}"
                        )
                        # Continue - the old system still works

                # Also add email/password provider if it doesn't exist
                if not oauth_token:
                    try:
                        unified_auth = UnifiedAuthService(db)
                        existing_email_provider = unified_auth.get_provider(
                            uid, "firebase_email"
                        )
                        if not existing_email_provider:
                            provider_create = AuthProviderCreate(
                                provider_type="firebase_email",
                                provider_uid=uid,
                                provider_data={"email": email, "uid": uid},
                                access_token=None,
                                is_primary=False,
                            )
                            unified_auth.add_provider(uid, provider_create)
                            logger.info(
                                f"Added firebase_email provider for existing user {uid}"
                            )
                    except Exception as e:
                        logger.warning(
                            f"Failed to add email provider for existing user: {str(e)}"
                        )

                return Response(
                    content=json.dumps({"uid": uid, "exists": True}),
                    status_code=200,
                )
            else:
                # Check if email already exists (from SSO signup) - need to link accounts
                if user_by_email:
                    logger.warning(
                        f"Email {email} already exists with UID {user_by_email.uid}, but new signup has UID {uid}. This should have been caught earlier."
                    )
                    # This shouldn't happen if the above check worked, but handle it anyway
                    return Response(
                        content=json.dumps(
                            {
                                "error": "Email already registered. Please sign in instead."
                            }
                        ),
                        status_code=400,
                    )

                # New user - create user
                first_login = datetime.now(timezone.utc)

                # Handle provider info for both GitHub OAuth and email/password
                if provider_data and len(provider_data) > 0:
                    provider_info = (
                        provider_data[0]
                        if isinstance(provider_data, list)
                        else provider_data
                    )
                    if oauth_token:
                        provider_info["access_token"] = oauth_token
                else:
                    # Email/password signup - create minimal provider info
                    provider_info = {
                        "providerId": "password",
                        "uid": uid,
                        "email": email,
                    }

                # For new users, use the email from the request
                # But if this is a GitHub signup and user exists by email, use existing email
                user_email = email
                if oauth_token and provider_data and len(provider_data) > 0:
                    # This is a GitHub signup - check if user exists by email
                    existing_user_by_email = user_service.get_user_by_email(email)
                    if existing_user_by_email:
                        # User exists - use their existing email (primary sign-in email)
                        user_email = existing_user_by_email.email
                        logger.info(
                            f"GitHub signup for existing email {email}. Using existing user email: {user_email}"
                        )

                user = CreateUser(
                    uid=uid,
                    email=user_email,  # Use existing email if user already exists
                    display_name=body.get("displayName", user_email.split("@")[0]),
                    email_verified=body.get("emailVerified", False),
                    created_at=first_login,
                    last_login_at=first_login,
                    provider_info=provider_info,
                    provider_username=provider_username,
                )
                uid, message, error = user_service.create_user(user)

                # Check if user creation failed due to duplicate email
                if (
                    error
                    and "duplicate" in message.lower()
                    or "already exists" in message.lower()
                ):
                    # Email already exists - try to link accounts
                    user_by_email = user_service.get_user_by_email(email)
                    if user_by_email:
                        logger.info(
                            f"User creation failed due to duplicate email. Linking {uid} to existing user {user_by_email.uid}"
                        )
                        # Update existing user's UID to match new Firebase UID
                        try:
                            user_by_email.uid = uid
                            db.commit()

                            # Add email/password provider
                            unified_auth = UnifiedAuthService(db)
                            provider_create = AuthProviderCreate(
                                provider_type="firebase_email",
                                provider_uid=uid,
                                provider_data={"email": email, "uid": uid},
                                access_token=None,
                                is_primary=False,
                            )
                            unified_auth.add_provider(uid, provider_create)

                            return Response(
                                content=json.dumps(
                                    {"uid": uid, "exists": True, "linked": True}
                                ),
                                status_code=200,
                            )
                        except Exception as e:
                            logger.error(
                                f"Error linking accounts after duplicate email error: {str(e)}"
                            )
                            db.rollback()

                # Also add provider in the new system
                try:
                    unified_auth = UnifiedAuthService(db)

                    # Determine provider type
                    if oauth_token and provider_data and len(provider_data) > 0:
                        # GitHub OAuth signup
                        provider_type = "firebase_github"
                        provider_info_data = (
                            provider_data[0]
                            if isinstance(provider_data, list)
                            else provider_data
                        )
                        provider_uid = provider_username or uid
                    else:
                        # Email/password signup - use firebase_email provider type
                        provider_type = "firebase_email"
                        provider_info_data = {"email": email, "uid": uid}
                        provider_uid = uid

                    provider_create = AuthProviderCreate(
                        provider_type=provider_type,
                        provider_uid=provider_uid,
                        provider_data=provider_info_data,
                        access_token=oauth_token if oauth_token else None,
                        is_primary=True,  # First provider is primary
                    )
                    unified_auth.add_provider(uid, provider_create)
                    logger.info(f"Added {provider_type} provider for new user {uid}")
                except Exception as e:
                    logger.warning(f"Failed to add provider for new user: {str(e)}")
                    import traceback

                    logger.warning(f"Traceback: {traceback.format_exc()}")
                    # Continue - the old system still works

                await send_slack_message(
                    f"New signup: {email} ({body.get('displayName', 'N/A')})"
                )

                PostHogClient().send_event(
                    uid,
                    "signup_event",
                    {
                        "email": email,
                        "display_name": body.get("displayName", ""),
                        "github_username": provider_username,
                    },
                )

                if error:
                    return Response(content=message, status_code=400)
                return Response(
                    content=json.dumps({"uid": uid, "exists": False}),
                    status_code=200,
                )
        except KeyError as e:
            logger.error(f"Missing required field in signup request: {str(e)}")
            return Response(
                content=json.dumps({"error": f"Missing required field: {str(e)}"}),
                status_code=400,
            )
        except Exception as e:
            logger.error(f"Error in signup endpoint: {str(e)}")
            import traceback

            logger.error(f"Traceback: {traceback.format_exc()}")
            return Response(
                content=json.dumps({"error": f"Signup failed: {str(e)}"}),
                status_code=500,
            )

    # ===== Multi-Provider SSO Endpoints =====

    @auth_router.post("/sso/login")
    async def sso_login(
        request: Request,
        sso_request: SSOLoginRequest,
        db: Session = Depends(get_db),
    ):
        """
        SSO Login endpoint.

        Handles login via any SSO provider (Google, Azure, Okta, SAML).
        Returns one of three statuses:
        - 'success': User authenticated
        - 'needs_linking': User exists with different provider, needs confirmation
        - 'new_user': New user created
        """
        try:
            unified_auth = UnifiedAuthService(db)

            # Get request context
            ip_address = request.client.host if request.client else None
            user_agent = request.headers.get("user-agent")

            # Map SSO provider to our provider type
            provider_type = f"sso_{sso_request.sso_provider}"

            # Verify the ID token with the SSO provider
            provider = unified_auth.get_sso_provider(sso_request.sso_provider)
            if not provider:
                logger.error(f"Unsupported SSO provider: {sso_request.sso_provider}")
                return JSONResponse(
                    content={
                        "error": f"Unsupported SSO provider: {sso_request.sso_provider}"
                    },
                    status_code=400,
                )

            # Verify token and extract user info
            try:
                user_info = await unified_auth.verify_sso_token(
                    sso_request.sso_provider, sso_request.id_token
                )
                if not user_info:
                    logger.error(
                        f"Token verification failed for {sso_request.sso_provider}"
                    )
                    return JSONResponse(
                        content={"error": "Invalid or expired ID token"},
                        status_code=401,
                    )

                # Use verified user info from token
                verified_email = user_info.email
                provider_uid = user_info.provider_uid
                display_name = user_info.display_name or verified_email.split("@")[0]
                email_verified = user_info.email_verified

                # Security: Verify that the email in the request matches the verified token email
                if sso_request.email.lower() != verified_email.lower():
                    logger.warning(
                        f"Email mismatch: request email {sso_request.email} does not match "
                        f"verified token email {verified_email}"
                    )
                    return JSONResponse(
                        content={
                            "error": "Email in request does not match verified token email"
                        },
                        status_code=400,
                    )

                # Build provider_data from verified token
                provider_data = sso_request.provider_data or {}
                provider_data["email"] = verified_email
                if user_info.raw_data:
                    provider_data.update(user_info.raw_data)

            except ValueError as e:
                logger.error(f"Token verification error: {str(e)}")
                return JSONResponse(
                    content={"error": f"Token verification failed: {str(e)}"},
                    status_code=401,
                )
            except Exception as e:
                logger.error(
                    f"Unexpected error verifying token: {str(e)}", exc_info=True
                )
                return JSONResponse(
                    content={"error": "Token verification failed"},
                    status_code=500,
                )

            # Authenticate or create user using verified email from token
            user, response = unified_auth.authenticate_or_create(
                email=verified_email,
                provider_type=provider_type,
                provider_uid=provider_uid,
                provider_data=provider_data,  # This includes the email for later retrieval
                display_name=display_name,
                email_verified=email_verified,
                ip_address=ip_address,
                user_agent=user_agent,
            )

            # Create Firebase custom token for frontend authentication
            # This allows the frontend to create a Firebase session
            # Skip in development mode where Firebase might not be initialized
            if os.getenv("isDevelopmentMode") == "enabled":
                logger.info(
                    "Development mode enabled - skipping Firebase custom token creation"
                )
            else:
                try:
                    import firebase_admin
                    from firebase_admin import auth as firebase_auth

                    # Check if Firebase is initialized
                    try:
                        firebase_app = firebase_admin.get_app()
                        logger.info("Firebase Admin is initialized")
                    except ValueError:
                        logger.error(
                            "Firebase Admin not initialized. Cannot create custom token."
                        )
                        logger.error("Make sure Firebase is initialized in app startup")
                        raise Exception("Firebase Admin not initialized")

                    # Create or get Firebase user
                    try:
                        firebase_user = firebase_auth.get_user_by_email(user.email)
                        # Update UID if it doesn't match
                        if firebase_user.uid != user.uid:
                            logger.warning(
                                f"Firebase UID mismatch: {firebase_user.uid} != {user.uid}"
                            )
                            # Use the Firebase UID for token creation
                            token_uid = firebase_user.uid
                        else:
                            token_uid = user.uid
                    except firebase_auth.UserNotFoundError:
                        # Create Firebase user if it doesn't exist
                        try:
                            firebase_user = firebase_auth.create_user(
                                uid=user.uid,
                                email=user.email,
                                display_name=user.display_name,
                                email_verified=True,
                            )
                            token_uid = user.uid
                            logger.info(
                                f"Created Firebase user {user.uid} for email {user.email}"
                            )
                        except firebase_auth.UidAlreadyExistsError:
                            # User exists with different email, get by UID
                            firebase_user = firebase_auth.get_user(user.uid)
                            token_uid = user.uid

                    # Generate custom token (returns bytes)
                    custom_token = firebase_auth.create_custom_token(token_uid)
                    # Decode bytes to string
                    response.firebase_token = custom_token.decode("utf-8")
                    logger.info(
                        f"Created Firebase custom token for user {token_uid} (email: {user.email})"
                    )
                except ImportError as e:
                    logger.error(f"Firebase Admin not available: {str(e)}")
                    logger.error(
                        "Cannot create custom token - Firebase Admin SDK not installed"
                    )
                except ValueError as e:
                    logger.error(f"Firebase Admin not initialized: {str(e)}")
                    logger.error(
                        "Cannot create custom token - Firebase not initialized"
                    )
                except Exception as firebase_error:
                    logger.error(
                        f"Failed to create Firebase custom token: {str(firebase_error)}"
                    )
                    logger.error(f"Error type: {type(firebase_error).__name__}")
                    import traceback

                    logger.error(f"Traceback: {traceback.format_exc()}")
                    # Continue without Firebase token - frontend can handle this

            # Send Slack notification for new users
            if response.status == "new_user":
                await send_slack_message(
                    f"New SSO signup: {verified_email} via {sso_request.sso_provider}"
                )

                PostHogClient().send_event(
                    user.uid,
                    "sso_signup_event",
                    {
                        "email": verified_email,
                        "sso_provider": sso_request.sso_provider,
                    },
                )

            # Include all fields including None values
            response_dict = response.model_dump(exclude_none=False)
            logger.info(
                f"SSO login response: status={response.status}, has_firebase_token={response.firebase_token is not None}"
            )
            return JSONResponse(
                content=response_dict,
                status_code=200 if response.status == "success" else 202,
            )

        except Exception as e:
            return JSONResponse(
                content={"error": f"SSO login failed: {str(e)}"},
                status_code=400,
            )

    @auth_router.post("/providers/confirm-linking")
    async def confirm_provider_linking(
        confirm_request: ConfirmLinkingRequest,
        db: Session = Depends(get_db),
    ):
        """
        Confirm linking a new provider to existing account.

        Called after user confirms they want to link the provider
        when 'needs_linking' status is returned from login.
        """
        try:
            if not confirm_request.linking_token:
                logger.error("Missing linking_token in request")
                return JSONResponse(
                    content={"error": "linking_token is required"},
                    status_code=400,
                )

            unified_auth = UnifiedAuthService(db)
            new_provider = unified_auth.confirm_provider_link(
                confirm_request.linking_token
            )

            if not new_provider:
                logger.warning("Invalid or expired linking token")
                return JSONResponse(
                    content={
                        "error": "Invalid or expired linking token. Please try signing in again."
                    },
                    status_code=400,
                )

            logger.info(
                f"Successfully linked provider {new_provider.provider_type} for user {new_provider.user_id}"
            )

            provider_response = AuthProviderResponse.model_validate(
                new_provider
            ).model_dump(mode="json")

            return JSONResponse(
                content={
                    "message": "Provider linked successfully",
                    "provider": provider_response,
                },
                status_code=200,
            )

        except ValueError as e:
            logger.error(f"ValueError in confirm_provider_linking: {str(e)}")
            return JSONResponse(
                content={"error": f"Invalid request: {str(e)}"},
                status_code=400,
            )
        except Exception as e:
            logger.error(
                f"Exception in confirm_provider_linking: {str(e)}", exc_info=True
            )
            return JSONResponse(
                content={"error": f"Failed to link provider: {str(e)}"},
                status_code=400,
            )

    @auth_router.delete("/providers/cancel-linking/{linking_token}")
    async def cancel_provider_linking(
        linking_token: str,
        db: Session = Depends(get_db),
    ):
        """Cancel a pending provider link"""
        try:
            unified_auth = UnifiedAuthService(db)
            success = unified_auth.cancel_pending_link(linking_token)

            if success:
                return JSONResponse(
                    content={"message": "Linking cancelled"},
                    status_code=200,
                )
            else:
                return JSONResponse(
                    content={"error": "Linking token not found"},
                    status_code=404,
                )

        except Exception as e:
            return JSONResponse(
                content={"error": f"Failed to cancel linking: {str(e)}"},
                status_code=400,
            )

    @auth_router.get("/providers/me")
    async def get_my_providers(
        request: Request,
        db: Session = Depends(get_db),
        credential: HTTPAuthorizationCredentials = Depends(
            HTTPBearer(auto_error=False)
        ),
    ):
        """
        Get all authentication providers for the current user.

        Requires authentication.
        """
        try:
            # Get user from auth token
            response = Response()
            user_data = await auth_handler.check_auth(request, response, credential)
            user_id = user_data.get("user_id")

            if not user_id:
                return JSONResponse(
                    content={"error": "Authentication required"},
                    status_code=401,
                )

            unified_auth = UnifiedAuthService(db)
            providers = unified_auth.get_user_providers(user_id)

            primary_provider = next((p for p in providers if p.is_primary), None)

            response = UserAuthProvidersResponse(
                providers=[AuthProviderResponse.model_validate(p) for p in providers],
                primary_provider=AuthProviderResponse.model_validate(primary_provider)
                if primary_provider
                else None,
            )

            return JSONResponse(
                content=response.model_dump(mode="json"),
                status_code=200,
            )

        except Exception as e:
            return JSONResponse(
                content={"error": f"Failed to get providers: {str(e)}"},
                status_code=400,
            )

    @auth_router.post("/providers/set-primary")
    async def set_primary_provider(
        request: Request,
        primary_request: SetPrimaryProviderRequest,
        db: Session = Depends(get_db),
        credential: HTTPAuthorizationCredentials = Depends(
            HTTPBearer(auto_error=False)
        ),
    ):
        """Set a provider as the primary login method"""
        try:
            # Get user from auth token
            response = Response()
            user_data = await auth_handler.check_auth(request, response, credential)
            user_id = user_data.get("user_id")

            if not user_id:
                return JSONResponse(
                    content={"error": "Authentication required"},
                    status_code=401,
                )

            unified_auth = UnifiedAuthService(db)
            success = unified_auth.set_primary_provider(
                user_id,
                primary_request.provider_type,
            )

            if success:
                return JSONResponse(
                    content={"message": "Primary provider updated"},
                    status_code=200,
                )
            else:
                return JSONResponse(
                    content={"error": "Provider not found"},
                    status_code=404,
                )

        except Exception as e:
            return JSONResponse(
                content={"error": f"Failed to set primary provider: {str(e)}"},
                status_code=400,
            )

    @auth_router.delete("/providers/unlink")
    async def unlink_provider(
        request: Request,
        unlink_request: UnlinkProviderRequest,
        db: Session = Depends(get_db),
        credential: HTTPAuthorizationCredentials = Depends(
            HTTPBearer(auto_error=False)
        ),
    ):
        """Unlink a provider from account"""
        try:
            # Get user from auth token
            response = Response()
            user_data = await auth_handler.check_auth(request, response, credential)
            user_id = user_data.get("user_id")

            if not user_id:
                return JSONResponse(
                    content={"error": "Authentication required"},
                    status_code=401,
                )

            unified_auth = UnifiedAuthService(db)

            try:
                success = unified_auth.unlink_provider(
                    user_id,
                    unlink_request.provider_type,
                )

                if success:
                    return JSONResponse(
                        content={"message": "Provider unlinked"},
                        status_code=200,
                    )
                else:
                    return JSONResponse(
                        content={"error": "Provider not found"},
                        status_code=404,
                    )

            except ValueError as ve:
                # Cannot unlink last provider
                return JSONResponse(
                    content={"error": str(ve)},
                    status_code=400,
                )

        except Exception as e:
            return JSONResponse(
                content={"error": f"Failed to unlink provider: {str(e)}"},
                status_code=400,
            )

    @auth_router.get("/account/check-email")
    async def check_email_providers(
        email: str,
        db: Session = Depends(get_db),
    ):
        """
        Check if an email exists and what providers it has.
        Used to help users who might have signed up with SSO.
        """
        try:
            user_service = UserService(db)
            user = user_service.get_user_by_email(email)

            if not user:
                return JSONResponse(
                    content={"exists": False, "has_sso": False},
                    status_code=200,
                )

            unified_auth = UnifiedAuthService(db)
            providers = unified_auth.get_user_providers(user.uid)

            # Check if user has SSO providers
            has_sso = any(p.provider_type.startswith("sso_") for p in providers)

            return JSONResponse(
                content={
                    "exists": True,
                    "has_sso": has_sso,
                    "providers": [p.provider_type for p in providers],
                },
                status_code=200,
            )
        except Exception as e:
            logger.error(f"Error checking email providers: {str(e)}")
            return JSONResponse(
                content={"error": "Failed to check email"},
                status_code=500,
            )

    @auth_router.get("/account/me")
    async def get_my_account(
        request: Request,
        db: Session = Depends(get_db),
        credential: HTTPAuthorizationCredentials = Depends(
            HTTPBearer(auto_error=False)
        ),
    ):
        """Get complete account information including all providers"""
        try:
            # Get user from auth token
            response = Response()
            user_data = await auth_handler.check_auth(request, response, credential)
            user_id = user_data.get("user_id")

            if not user_id:
                return JSONResponse(
                    content={"error": "Authentication required"},
                    status_code=401,
                )

            user_service = UserService(db)
            user = user_service.get_user_by_uid(user_id)

            if not user:
                return JSONResponse(
                    content={"error": "User not found"},
                    status_code=404,
                )

            unified_auth = UnifiedAuthService(db)
            providers = unified_auth.get_user_providers(user_id)

            primary_provider_obj = next((p for p in providers if p.is_primary), None)
            primary_provider = (
                primary_provider_obj.provider_type if primary_provider_obj else None
            )

            # Determine the correct email to return based on primary provider
            # Logic:
            # 1. If primary provider is GitHub → show GitHub email
            # 2. If primary provider is SSO (Google) → show SSO email
            # 3. If primary provider is email/password → show email/password email
            # 4. Otherwise → use database email
            display_email = user.email  # Default to database email

            if primary_provider_obj:
                # Get email from primary provider's data
                if primary_provider_obj.provider_data:
                    provider_email = primary_provider_obj.provider_data.get("email")
                    if provider_email:
                        display_email = provider_email
            else:
                # No primary provider - try to find best email
                # Priority: SSO > Email/Password > GitHub > Database
                sso_provider = next(
                    (p for p in providers if p.provider_type.startswith("sso_")), None
                )
                if sso_provider and sso_provider.provider_data:
                    provider_email = sso_provider.provider_data.get("email")
                    if provider_email:
                        display_email = provider_email

                # If no SSO, try email/password provider
                if display_email == user.email:
                    email_provider = next(
                        (p for p in providers if p.provider_type == "firebase_email"),
                        None,
                    )
                    if email_provider and email_provider.provider_data:
                        provider_email = email_provider.provider_data.get("email")
                        if provider_email:
                            display_email = provider_email

                # If still database email, try GitHub provider (last resort)
                if display_email == user.email:
                    github_provider = next(
                        (p for p in providers if p.provider_type == "firebase_github"),
                        None,
                    )
                    if github_provider and github_provider.provider_data:
                        provider_email = github_provider.provider_data.get(
                            "email"
                        ) or github_provider.provider_data.get("login")
                        if provider_email:
                            display_email = provider_email

            response = AccountResponse(
                user_id=user.uid,
                email=display_email,  # Use the determined display email
                display_name=user.display_name,
                organization=user.organization,
                organization_name=user.organization_name,
                email_verified=user.email_verified,
                created_at=user.created_at,
                providers=[
                    AuthProviderResponse.model_validate(p).model_dump(mode="json")
                    for p in providers
                ],
                primary_provider=primary_provider,
            )

            return JSONResponse(
                content=response.model_dump(mode="json"),
                status_code=200,
            )

        except Exception as e:
            return JSONResponse(
                content={"error": f"Failed to get account: {str(e)}"},
                status_code=400,
            )
