from thefuzz import fuzz

MOCK_PREFIX = 'mock_'

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

    modified_src = src.removeprefix(MOCK_PREFIX)

    # first character must match, case insensitve
    if modified_src[0].lower() != target[0].lower():
        return None

    # if length of what user wants to complete is longer then target
    # remove this target
    target_length = len(target)
    if len(modified_src) > target_length:
        return None

    # modify the target to boost the score
    modified_target = target.replace("_", "").lower()

    fuzz_ratio_score = fuzz.ratio(modified_src, modified_target)

    score = fuzz_ratio_score

    # boost score by the length of target
    # prioritise completing long words
    score += target_length

    if src.startswith(MOCK_PREFIX) and not target.startswith(MOCK_PREFIX):
        return -1 * score, f"{MOCK_PREFIX}{target}"
    else:
        return -1 * score, target

def check_subseq(src, target):
    """Check if src is a subsequence of target.

    this check_subseq has the nice property that the string length similarity doesn't matter

    I want a fuzzy algorithm that the string length similarity doesn't matter
    """
    if not src:
        return 0

    score = i = 0
    src, target = src.lower(), target.lower()
    src_len, target_len = len(src), len(target)
    for index, e in enumerate(target):
        if src_len - i > target_len - index:
            return
        if e != src[i]:
            continue
        if index == 0:
            score = -999
        score += index
        i += 1
        if i == src_len:
            return score

def test_check_subseq():
    assert check_subseq("abc", "abc") == -996
    assert check_subseq("abc", "abcde") == -996

def test_check_subseq_fuzzy():
    assert check_subseq_fuzzy("abc", "abc") == (-100 - 3, "abc")
    assert check_subseq_fuzzy("mock_abc", "abc") == (-100 - 3, "mock_abc")
