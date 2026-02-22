"""
LogCentry CLI - Zero-Knowledge Authentication
"""

import base64
import getpass
import hashlib
import hmac
import os
import secrets
import requests
from rich.console import Console
from rich.panel import Panel

console = Console()

def encode_base64(data: bytes) -> str:
    return base64.b64encode(data).decode('utf-8')

def decode_base64(data: str) -> bytes:
    return base64.b64decode(data)

def derive_verifier(password: str, salt: bytes) -> bytes:
    """
    Derive password verifier using Argon2id.
    """
    try:
        from argon2.low_level import hash_secret_raw, Type
        
        # Argon2id parameters (RFC 9106 recommended)
        # Time cost: 1, Memory cost: 64MB, Parallelism: 4, Hash length: 32
        return hash_secret_raw(
            secret=password.encode('utf-8'),
            salt=salt,
            time_cost=1,
            memory_cost=64 * 1024,
            parallelism=4,
            hash_len=32,
            type=Type.ID,
        )
    except ImportError:
        console.print("[red]Error: argon2-cffi is not installed. Please install it to use ZK auth.[/]")
        console.print("pip install argon2-cffi")
        return b""

def run_register_zk(args):
    """Register a new user using Zero-Knowledge Proof."""
    console.print(Panel("🔐 [bold]Zero-Knowledge Registration[/]"))
    
    server_url = f"http://{args.server_host}:{args.server_port}"
    
    # Get user input
    email = input("Email: ").strip()
    username = input("Username: ").strip()
    password = getpass.getpass("Password: ")
    confirm = getpass.getpass("Confirm Password: ")
    
    if password != confirm:
        console.print("[red]Passwords do not match![/]")
        return

    console.print("\n[dim]Generating cryptographic proofs...[/]")
    
    # 1. Generate random salt
    salt = secrets.token_bytes(16)
    
    # 2. Derive verifier
    verifier = derive_verifier(password, salt)
    if not verifier:
        return
        
    # 3. Send to server
    payload = {
        "email": email,
        "username": username,
        "salt": encode_base64(salt),
        "verifier": encode_base64(verifier),
    }
    
    try:
        response = requests.post(f"{server_url}/api/v1/auth/signup-zk", json=payload)
        
        if response.status_code == 200:
            console.print("[bold green]✓ Registration Successful![/]")
            console.print("[dim]The server has received your verifier but NOT your password.[/]")
        else:
            console.print(f"[red]Registration Failed: {response.text}[/]")
            
    except Exception as e:
        console.print(f"[red]Connection Error: {e}[/]")


def run_login_zk(args):
    """Login using Zero-Knowledge Proof."""
    console.print(Panel("🔐 [bold]Zero-Knowledge Login[/]"))
    
    server_url = f"http://{args.server_host}:{args.server_port}"
    
    email = input("Email: ").strip()
    password = getpass.getpass("Password: ")
    
    console.print("\n[dim]1. Requesting challenge...[/]")
    
    try:
        # Step 1: Request Challenge
        resp = requests.post(f"{server_url}/api/v1/auth/login-zk/challenge", json={"email": email})
        
        if resp.status_code != 200:
            console.print(f"[red]Login Failed: {resp.text}[/]")
            return
            
        data = resp.json()
        salt_b64 = data["salt"]
        challenge_b64 = data["challenge"]
        login_token = data["login_token"]
        
        # Step 2: Compute Proof
        console.print("[dim]2. Computing proof (Argon2id + HMAC)...[/]")
        
        salt = decode_base64(salt_b64)
        challenge = decode_base64(challenge_b64)
        
        verifier = derive_verifier(password, salt)
        if not verifier:
            return
            
        # HMAC(verifier, challenge)
        h = hmac.new(verifier, challenge, hashlib.sha256)
        proof = h.digest()
        
        # Step 3: Verify
        console.print("[dim]3. Verifying proof...[/]")
        
        resp = requests.post(f"{server_url}/api/v1/auth/login-zk/verify", json={
            "login_token": login_token,
            "proof": encode_base64(proof),
        })
        
        if resp.status_code == 200:
            token_data = resp.json()
            access_token = token_data["access_token"]
            
            console.print("[bold green]✓ Login Successful![/]")
            console.print(f"\n[bold]Access Token:[/]\n{access_token[:50]}...")
            
            # Save token if needed, or just display
        else:
            console.print(f"[red]Authentication Failed: {resp.text}[/]")
            
    except Exception as e:
        console.print(f"[red]Error: {e}[/]")
