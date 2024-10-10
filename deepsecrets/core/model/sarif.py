from typing import List, Optional
from pydantic import BaseModel, Field
from enum import Enum
from deepsecrets.config import SCANNER_NAME, SCANNER_URL, SCANNER_VERSION

'''
{
  "version": "2.1.0",
  "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
  "runs": [
    {
      "tool": {
        "driver": {
          "name": "OWASP DeepSecrets",
          "semanticVersion": "v1.2.0",
          "informationUri": "https://github.com/ntoskernel/deepsecrets",
          "properties": {
            "protocol_version": "v1.2.0",
            "scanner_name": "OWASP DeepSecrets",
            "scanner_version": "v1.2.0",
            "scan_mode": "source"
          },
          "rules": [ 
            {
              "id": "rule-id",
              "shortDescription": {
                "text": "Found secret in code"
              },
              "fullDescription": {
                "text": "Some rule description"
              },
              "help": {
                "text": "Some rule description"
              },
              "properties": {
                "precision": "(low|medium|high|very-high)",
                "security-severity": "(Info|Low|Medium|High|Critical)",
                "tags": [
                    "pem",
                    "token",
                    "enthropy"
                ]
              },
              "defaultConfiguration": {
                "level": "(error|warning|note)"
              },
          ]
        }
      },
      "results": [ 
        {
          "ruleId": "rule-id",
          "message": {
            "text": "Title of vuln"
          },
          "locations": [
            {
              "physicalLocation": {
                "artifactLocation": {
                  "uri": "local/file/path.py",
                  "uriBaseId": "%SRCROOT%"
                },
                "region": {
                    "startLine": 83,
                    "snippet": {
                        "text": "\t\t some_token=dddd\n"
                    }
                }
              }
            }
          ]
        }
      ]
    }
  ]
}


'''

class LevelEnum(str, Enum):
    error = "error"
    warning = "warning"
    note = "note"

class PrecisionEnum(str, Enum):
    low = "low"
    medium = "medium"
    high = "high"
    very_high = "very-high"

class SecuritySeverityEnum(str, Enum):
    info = "Info"
    low = "Low"
    medium = "Medium"
    high = "High"
    critical = "Critical"

class RuleShortDescription(BaseModel):
    text: str = ""

class RuleFullDescription(BaseModel):
    text: str = ""

class RuleHelp(BaseModel):
    text: str = ""

class RuleProperties(BaseModel):
    precision: PrecisionEnum = PrecisionEnum.medium
    security_severity: SecuritySeverityEnum = SecuritySeverityEnum.medium
    tags: List[str] = []

class RuleDefaultConfiguration(BaseModel):
    level: LevelEnum = LevelEnum.error

class Rule(BaseModel):
    id: str
    shortDescription: RuleShortDescription = RuleShortDescription()
    fullDescription: RuleFullDescription = ()
    help: RuleHelp = RuleHelp()
    properties: RuleProperties = RuleProperties()
    defaultConfiguration: RuleDefaultConfiguration = RuleDefaultConfiguration()

class DriverProperties(BaseModel):
    protocol_version: str = SCANNER_VERSION
    scanner_name: str = SCANNER_NAME
    scanner_version: str = SCANNER_VERSION
    scan_mode: str = "source"

class Driver(BaseModel):
    name: str = SCANNER_NAME
    semanticVersion: str = SCANNER_VERSION
    informationUri: str = SCANNER_URL
    properties: DriverProperties = DriverProperties()
    rules: List[Rule] = []

class Tool(BaseModel):
    driver: Driver = Driver()

class ArtifactLocation(BaseModel):
    uri: str
    uriBaseId: str = "%SRCROOT%"

class RegionSnippet(BaseModel):
    text: str

class Region(BaseModel):
    startLine: int = 0
    snippet: Optional[RegionSnippet]

class PhysicalLocation(BaseModel):
    artifactLocation: ArtifactLocation
    region: Region

class Location(BaseModel):
    physicalLocation: PhysicalLocation

class Message(BaseModel):
    text: str

class Result(BaseModel):
    ruleId: str
    message: Message
    locations: List[Location]

class Run(BaseModel):
    tool: Tool
    results: List[Result] = []

class Sarif(BaseModel):
    version: str = "2.1.0"
    sarif_schema: str = Field(alias='schema', default="https://json.schemastore.org/sarif-2.1.0.json") 
    runs: List[Run] = []