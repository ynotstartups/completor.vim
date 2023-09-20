from thefuzz import fuzz

def check_subseq_fuzzy(src: str, target: str) -> int | None:
    """Check if src is a subsequence of target.

    :param src:    what user types
    :param target: a word in buffer

    :return score:
    """
    if not src:
        return None

    mock_prefix = 'mock_'
    if src.startswith(mock_prefix):
        src = src.removeprefix(mock_prefix)

    target_length = len(target)
    # first character must match
    if src[0].lower() != target[0].lower():
        return None

    # if length of what user wants to complete is longer then target
    # remove this target
    if len(src) > target_length:
        return None

    fuzz_ratio_score = fuzz.ratio(src, target)
    # fuzz_partial_ratio_score = fuzz.partial_ratio(src, target)

    score = fuzz_ratio_score
    # score += fuzz_partial_ratio_score

    # boost score by the length of target
    # prioritise completing long words
    score += target_length

    return -1 * score
