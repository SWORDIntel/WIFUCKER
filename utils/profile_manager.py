#!/usr/bin/env python3
"""
Profile Manager
===============

Manages configuration profiles for saving and reusing common configurations.
"""

import json
from pathlib import Path
from typing import Dict, Optional, List
from dataclasses import dataclass, asdict


@dataclass
class Profile:
    """Configuration profile"""
    name: str
    description: Optional[str] = None
    command: str = ""
    args: Dict = None
    
    def __post_init__(self):
        if self.args is None:
            self.args = {}


class ProfileManager:
    """Manage configuration profiles"""
    
    def __init__(self, profiles_dir: Optional[Path] = None):
        if profiles_dir is None:
            profiles_dir = Path.home() / ".wifucker" / "profiles"
        self.profiles_dir = profiles_dir
        self.profiles_dir.mkdir(parents=True, exist_ok=True)
    
    def save_profile(self, profile: Profile) -> bool:
        """Save profile to disk"""
        try:
            profile_file = self.profiles_dir / f"{profile.name}.json"
            profile_file.write_text(json.dumps(asdict(profile), indent=2))
            return True
        except Exception:
            return False
    
    def get_profile(self, name: str) -> Optional[Profile]:
        """Get profile by name"""
        profile_file = self.profiles_dir / f"{name}.json"
        if not profile_file.exists():
            return None
        
        try:
            data = json.loads(profile_file.read_text())
            return Profile(**data)
        except Exception:
            return None
    
    def list_profiles(self) -> List[Profile]:
        """List all profiles"""
        profiles = []
        for profile_file in self.profiles_dir.glob("*.json"):
            try:
                data = json.loads(profile_file.read_text())
                profiles.append(Profile(**data))
            except Exception:
                continue
        
        return sorted(profiles, key=lambda p: p.name)
    
    def delete_profile(self, name: str) -> bool:
        """Delete profile"""
        profile_file = self.profiles_dir / f"{name}.json"
        if not profile_file.exists():
            return False
        
        try:
            profile_file.unlink()
            return True
        except Exception:
            return False
    
    def create_from_args(self, name: str, command: str, args: Dict, description: Optional[str] = None) -> Profile:
        """Create profile from command arguments"""
        profile = Profile(
            name=name,
            description=description,
            command=command,
            args=args
        )
        self.save_profile(profile)
        return profile

