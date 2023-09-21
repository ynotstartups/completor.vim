from thefuzz import fuzz

def check_subseq_fuzzy(src: str, target: str) -> tuple[int, str] | None:
    """Check if src is a subsequence of target.

    1. support completion when I want to mock a function in python
       in the following case
        
        @mock.patch("foo.bar.export_duplicates")
        def test_foo(self, mock_e?):

    :param src:    what user types
    :param target: a word in buffer

    :return score:
    """
    if not src:
        return None

    original_src = src
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

    score = fuzz_ratio_score

    # boost score by the length of target
    # prioritise completing long words
    score += target_length

    if original_src.startswith("mock_") and not target.startswith("mock_"):
        return -1 * score, f"mock_{target}"
    else:
        return -1 * score, target

def test_check_subseq_fuzzy():
    assert check_subseq_fuzzy("abc", "abc") == (-100 - 3, "abc")
    assert check_subseq_fuzzy("mock_abc", "abc") == (-100 - 3, "mock_abc")
