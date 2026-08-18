# ui/colors.py
# Minimal Dark Theme — neutral grayscale surfaces, one calm accent, desaturated status colors.

# --- Surfaces ---
BG_MAIN = "#09090B"        # Outer window background (near-black, neutral)
BG_SIDEBAR = "#0D0D0F"     # Sidebar background
BG_CARD_1 = "#131316"      # Cards / stat tiles
BG_CARD_2 = "#18181B"      # Inputs, nested elements, terminal
BG_CARD_HOVER = "#1E1E22"  # Hover state for neutral surfaces

# --- Borders ---
BORDER = "#212124"         # Default hairline border (subtle, near-invisible at rest)
BORDER_STRONG = "#2C2C31"  # Hover / active border, secondary button hover

# --- Text ---
TEXT_MAIN = "#EDEDEF"
TEXT_MUTED = "#8B8B93"
TEXT_DIM = "#59595F"

# --- Accent (single, used sparingly for actions/focus) ---
ACCENT_PRIMARY = "#6366F1"
ACCENT_PRIMARY_HOVER = "#4F51D6"

# --- Status accents (desaturated so they sit quietly on the dark surface) ---
ACCENT_SUCCESS = "#3EB97C"
ACCENT_SUCCESS_HOVER = "#2F9C67"

ACCENT_ERROR = "#E5484D"
ACCENT_ERROR_HOVER = "#C93D42"

ACCENT_WARNING = "#D6A24A"
ACCENT_WARNING_HOVER = "#B98A3B"

ACCENT_PURPLE = "#8D85E8"   # secondary accent for the "Names found" tile

# --- Table-specific tokens ---
BG_TABLE_HEADER = "#101012"  # Treeview header row
BG_SELECTED = "#201F2C"      # Selected table row — tinted, not a solid accent block

# --- Text placed directly on a solid accent fill ---
TEXT_ON_ACCENT = "#FFFFFF"
TEXT_ON_WARNING = "#15110A"
