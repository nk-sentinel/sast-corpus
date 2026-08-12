fun render(user: String): String {
    val flat = user.replace("\n", "").replace("\r", "")
    return "level=info action=login user=" + flat
}
