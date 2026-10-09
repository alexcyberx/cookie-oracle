import typer
import json
import asyncio
import pyfiglet
from rich.console import Console, Group
from rich.table import Table
from rich.panel import Panel
from rich.text import Text
from rich.align import Align
from rich.columns import Columns

from cookie_oracle.core.cookie_parser import parse_cookie_string, get_cookie_metadata
from cookie_oracle.detectors.platform_detector import detect_platform
from cookie_oracle.analyzers.risk_scorer import calculate_risk_score, get_risk_level, generate_exploitation_matrix
from cookie_oracle.validators.session_validator import SessionValidator

console = Console()
app = typer.Typer(help="Cookie-Oracle: Advanced Session Intelligence Engine")

# Small pixel-style logo (cookie with a crack), built from Unicode blocks
LOGO_LINES = [
    "  ▄▟▓▓▓▙▄  ",
    " ▟▓▓░▓░▓▓▙ ",
    " ▓▓░▓▓▓░▓▓ ",
    " ▓░▓▓▞▚▓░▓ ",
    " ▜▓▓▚░░▞▓▛ ",
    "   ▜▓▓▓▛   ",
]

def _make_logo() -> Text:
    logo = Text()
    for line in LOGO_LINES:
        logo.append(line + "\n", style="bold cyan")
    return logo

def _make_title(width: int) -> Text:
    # Pick a figlet font (and single-line vs stacked word) that fits the
    # current terminal width, so it stays readable on a phone screen too.
    if width >= 100:
        art = pyfiglet.figlet_format("COOKIE-ORACLE", font="standard")
    elif width >= 70:
        art = pyfiglet.figlet_format("COOKIE-ORACLE", font="small")
    elif width >= 40:
        art = (
            pyfiglet.figlet_format("COOKIE", font="small")
            + pyfiglet.figlet_format("ORACLE", font="small")
        )
    else:
        art = (
            pyfiglet.figlet_format("COOKIE", font="mini")
            + pyfiglet.figlet_format("ORACLE", font="mini")
        )
    return Text(art, style="bold magenta")

def print_banner():
    width = console.size.width

    logo = _make_logo()
    title = _make_title(width)

    subtitle = Text(justify="center")
    subtitle.append("Session Intelligence Engine ", style="bold cyan")
    subtitle.append("v1.0\n", style="bold yellow")
    subtitle.append("github.com/alexcyberx/cookie-oracle", style="yellow")

    # Side by side on wide terminals, stacked on narrow/mobile ones
    logo_width = max(len(line) for line in LOGO_LINES)
    if width >= logo_width + max(len(l) for l in title.plain.splitlines() or [""]) + 10:
        header = Columns([logo, title], align="center", expand=False)
    else:
        header = Group(Align.center(logo), Align.center(title))

    banner = Group(header, Align.center(subtitle))

    console.print(
        Panel(
            banner,
            border_style="magenta",
            padding=(1, 2),
        )
    )

@app.command()
def analyze(
    cookie: str = typer.Option(..., "--cookie", "-c", help="Full cookie string"),
    domain: str = typer.Option(None, "--domain", "-d", help="Target domain"),
    output: str = typer.Option("terminal", "--output", "-o", help="Output format: terminal/json/csv"),
    privilege: str = typer.Option("unknown", "--privilege", "-p", help="Known privilege level")
):
    """Analyze a session cookie for platform, validity, and risks."""
    print_banner()
    cookie_dict = parse_cookie_string(cookie)
    flags_list = get_cookie_metadata(cookie_dict)
    platform_result = detect_platform(cookie_dict, domain)
    primary_platform = platform_result[0]['platform']

    report = {
        "platform": primary_platform,
        "confidence": platform_result[0]['confidence'],
        "privilege_guess": privilege,
        "cookies": flags_list,
        "exploitation_matrix": [],
        "risk_score": 0,
        "risk_level": "",
        "session_status": {}
    }

    for flags in flags_list:
        risk_score = calculate_risk_score(primary_platform, flags, privilege)
        report["risk_score"] = risk_score
        report["risk_level"] = get_risk_level(risk_score)
        report["exploitation_matrix"] = generate_exploitation_matrix(flags)

    # Session validity check
    validator = SessionValidator()
    report["session_status"] = asyncio.run(validator.probe_session(cookie_dict, domain, primary_platform))

    # Output handling
    if output == "json":
        console.print_json(json.dumps(report, indent=2))
    else:
        console.print(Panel(f"[bold]Platform:[/bold] {primary_platform} [dim]({report['confidence']}% confidence)[/dim]"))
        console.print(f"[bold]Risk Score:[/bold] {report['risk_score']} - [bold {report['risk_level'].lower()}]{report['risk_level']}[/bold {report['risk_level'].lower()}]")
        console.print(f"[bold]Privilege Guess:[/bold] {privilege}")
        session_status = report["session_status"]
        status_color = "green" if session_status["status"] == "active" else "red" if session_status["status"] == "expired" else "yellow"
        console.print(f"[bold]Session Status:[/bold] [{status_color}]{session_status['status']}[/{status_color}] ({session_status.get('confidence', 0)}% confidence)")

        table = Table(title="Exploitation Matrix")
        table.add_column("Method")
        table.add_column("Possible?")
        table.add_column("Notes")
        for item in report["exploitation_matrix"]:
            status = "[green]Yes[/green]" if item['possible'] else "[red]No[/red]"
            table.add_row(item['method'], status, item['notes'])
        console.print(table)

@app.command()
def batch(
    file_path: str = typer.Option(..., "--file", "-f", help="Text file with one cookie per line"),
    domain: str = typer.Option(None, "--domain", "-d"),
    privilege: str = typer.Option("unknown", "--privilege", "-p", help="Default privilege level")
):
    """Analyze multiple cookies from a file with full intelligence."""
    print_banner()
    validator = SessionValidator()
    with open(file_path, 'r') as f:
        lines = f.readlines()
    results = []
    for line in lines:
        line = line.strip()
        if line:
            cookie_dict = parse_cookie_string(line)
            platform_result = detect_platform(cookie_dict, domain)
            primary_platform = platform_result[0]['platform']
            flags_list = get_cookie_metadata(cookie_dict)
            session_status = asyncio.run(validator.probe_session(cookie_dict, domain, primary_platform))

            # Calculate risk using first cookie's flags
            flags = flags_list[0] if flags_list else {}
            risk_score = calculate_risk_score(primary_platform, flags, privilege)

            results.append({
                "platform": primary_platform,
                "confidence": platform_result[0]['confidence'],
                "session_status": session_status.get("status", "unknown"),
                "risk_score": risk_score,
                "risk_level": get_risk_level(risk_score)
            })

    # Summary table
    table = Table(title="Batch Analysis Results")
    table.add_column("Platform", style="cyan")
    table.add_column("Confidence", style="magenta")
    table.add_column("Status", style="green")
    table.add_column("Risk Score", style="yellow")
    table.add_column("Risk Level", style="red")

    for r in results:
        table.add_row(
            r["platform"],
            f"{r['confidence']}%",
            r["session_status"],
            str(r["risk_score"]),
            r["risk_level"]
        )
    console.print(table)

    # Also output JSON for automation
    console.print("\n[bold]JSON Output:[/bold]")
    console.print_json(json.dumps(results, indent=2))

@app.command()
def serve(
    host: str = typer.Option("127.0.0.1", "--host", help="Host to bind to"),
    port: int = typer.Option(8000, "--port", "-p", help="Port to run on")
):
    """Start the Cookie-Oracle web dashboard."""
    import uvicorn
    from fastapi.responses import HTMLResponse
    from cookie_oracle.web.server import app as web_app

    # Mount CLI app under /api/cli for direct access
    @web_app.get("/cli")
    async def cli_info():
        return HTMLResponse("<h1>Cookie-Oracle CLI Mode</h1><p>Use terminal with 'python -m cookie_oracle'.</p>")

    console.print(f"[bold green]Starting Cookie-Oracle Web Dashboard...[/bold green]")
    console.print(f"[dim]Access at: http://{host}:{port}[/dim]")
    console.print("[dim]Press CTRL+C to stop[/dim]")

    uvicorn.run(web_app, host=host, port=port)

if __name__ == "__main__":
    app()