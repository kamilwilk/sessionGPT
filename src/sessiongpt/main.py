from typing import Annotated, List, Literal

import marvin
import typer
from pydantic import BaseModel, Field, StringConstraints, field_validator


class IAMPolicyStatement(BaseModel):
    Sid: Annotated[
        str,
        StringConstraints(pattern=r"^([a-zA-Z0-9]+)*"),
    ] = Field(..., description="AWS IAM policy statement identifier")
    Effect: str = Field(..., description="Either 'Allow' or 'Deny'")
    Action: List[str] = Field(
        ..., description="AWS IAM policy actions that the statement will allow or deny"
    )
    Resource: List[str] = Field(
        ...,
        description="AWS ARNs of the resources that the actions will be allowed or denied on",
    )

    @field_validator("Effect")
    def validate_effect(cls, value):
        if value not in ["Allow", "Deny"]:
            raise ValueError("Effect must be either 'Allow' or 'Deny'")
        return value


class IAMSessionPolicy(BaseModel):
    Version: Literal["2012-10-17"]
    Statement: List[IAMPolicyStatement]


app = typer.Typer(add_completion=False)


@app.command()
def generate(
    description: str = typer.Option(
        help="A description of the tasks needed to be performed in the AWS session."
    ),
    pretty: bool = typer.Option(help="Pretty print the session policy.", default=False),
):
    result = marvin.cast(
        data=description,
        target=IAMSessionPolicy,
        instructions=(
            "You are a security engineer. Your job is to create a new AWS IAM session policy for a user."
            + " The session policy shoud allow the user to perform their tasks but adhere to principle of least privilege."
            + " Do NOT include delete actions in the policy unless the user explicitly asks for them."
        ),
    )
    indent = 2 if pretty else None
    typer.echo(result.model_dump_json(indent=indent))


def cli():
    app()
