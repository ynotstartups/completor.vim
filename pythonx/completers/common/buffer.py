# -*- coding: utf-8 -*-

import collections
import itertools
import re
import logging

from completor import Completor, vim, LIMIT, get_encoding as get_current_buffer_encoding
from completor.compat import to_unicode, to_bytes

from difflib import SequenceMatcher

logger = logging.getLogger('completor')
word_re_pattern = re.compile(r'[^\W\d]\w*$', re.U)

MOCK_PREFIX = 'mock_'
TEST_PREFIX = 'test_'

def similarity(a, b):
    return SequenceMatcher(None, a, b).ratio()

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

    # when we want to complete `test_`, we are looking for a function not other
    # test names
    if src.startswith(TEST_PREFIX) and target.startswith(TEST_PREFIX):
        return None
    elif src.startswith(MOCK_PREFIX) and target.startswith(MOCK_PREFIX):
        return None

    modified_src = src.removeprefix(MOCK_PREFIX).removeprefix(TEST_PREFIX)

    # first character must match, case sensitve
    if modified_src[0] != target[0]:
        return None

    # if length of what user wants to complete is longer then target
    # remove this target
    target_length = len(target)
    if len(modified_src) > target_length:
        return None

    # modify the target to boost the score

    # optimise for searching for typing `asscall` to return `_assert_called_once_with`
    # instead of returning `assertEqual`
    # because I realised that I tend to type in the first few characters of
    # each word to look for a longer word
    modified_target = "".join([word[:3] for word in target.split('_')])

    # score = fuzz.ratio(modified_src, modified_target)
    score = similarity(modified_src, modified_target)

    # boost score by the length of target
    # prioritise completing long words
    # score += min(target_length, 10)

    if src.startswith(MOCK_PREFIX) and not target.startswith(MOCK_PREFIX):
        return -1 * score, f"{MOCK_PREFIX}{target}"
    elif src.startswith(TEST_PREFIX):
        # when targets is a private function `_foo_bar`
        # we remove the additional `_`
        return -1 * score, f"{TEST_PREFIX}{target.removeprefix('_')}"
    else:
        return -1 * score, target


def getftime(nr):
    try:
        bufname = vim.Function('bufname')
        ftime = vim.Function('getftime')
        return ftime(bufname(nr))
    except vim.error:
        return -1


def get_encoding(nr):
    try:
        getbufvar = vim.Function('getbufvar')
        encoding = getbufvar(nr, '&encoding')
    except vim.error:
        encoding = ''
    return to_unicode(encoding or 'utf-8', 'utf-8')


class TokenStore(object):
    # Previous pattern ignores words with digits in the first 3 characters
    # which doesn't work for words in oneview codebase such as t4a_curoholding
    # So I removed the `\d` from the pattern
    # pat = re.compile(r'[^\W\d]{3}\w{0,45}', re.U)

    # \W - Matches any non-alphanumeric character; this is equivalent to the class [^a-zA-Z0-9_]
    # \w - Matches any alphanumeric character; this is equivalent to the class [a-zA-Z0-9_].
    pat = re.compile(r'[^\W]{3}\w{0,45}', re.U)

    def __init__(self):
        logger.info(f"\033[36m TokenStore init \033[0m")
        self.cache = {}
        self.store = collections.deque(maxlen=10000)
        self.current = set()
        

    def search(self, src) -> tuple[str, int]:
        logger.info(f"\033[36m TokenStore search \033[0m")
        """
        src is what user typed and wanted it to be completed
        """
        words = itertools.chain(self.current, self.store)
        logger.info(f"\033[36m self.current {sorted(self.current)}\033[0m")
        logger.info(f"\033[36m self.store {sorted(self.store)}\033[0m")
        for token in words:
            logger.info(f"\033[36m token {token}\033[0m")
            result = check_subseq_fuzzy(src, token)
            if result is None:
                continue
            score, updated_token = result

            yield updated_token, score


    def store_buffer(self, buffer, src, cur_nr, cur_line):
        logger.info(f"\033[36m store buffer \033[0m")
        nr = buffer.number
        encoding = get_encoding(nr)

        if nr == cur_nr:
            start = cur_line - 1000
            end = cur_line + 1000
            if start < 0:
                start = 0
            data = ' '.join(itertools.chain(buffer[start:cur_line],
                                            buffer[cur_line + 1:end]))
            self.current = set(self.pat.findall(to_unicode(data, encoding)))
            self.current.difference_update([src])
        elif buffer.valid and len(buffer) <= 10000:
            ftime = getftime(nr)
            if ftime < 0:
                return
            if nr not in self.cache or ftime > self.cache[nr]['t']:
                self.cache[nr] = {'t': ftime}
                data = to_unicode(' '.join(buffer[:]), encoding)
                words = set(self.store)
                words.update(set(self.pat.findall(data)))
                self.store.clear()
                self.store.extend(words)

        logger.info(f"\033[36m store buffer end \033[0m")

    def parse_buffers(self, src):
        logger.info(f"\033[36m parse buffers \033[0m")
        nr = vim.current.buffer.number
        line, _ = vim.current.window.cursor

        for buffer in vim.buffers:
            self.store_buffer(buffer, src, nr, line)
        logger.info(f"\033[36m parse buffers end \033[0m")


token_store = TokenStore()

class Buffer(Completor):
    filetype = 'buffer'
    sync = True

    def parse(self, user_src):
        logger.info(f"\033[36m Buffer parse \033[0m")
        re_match = word_re_pattern.search(user_src)
        if not re_match:
            return []
        src = re_match.group()
        if len(src) < self.get_option('min_chars'):
            return []
        logger.info(f"\033[36m start token_store.parse_buffers(src) \033[0m")
        token_store.parse_buffers(src)
        logger.info(f"\033[36m end token_store.parse_buffers(src) \033[0m")

        res = set()
        for token, score in token_store.search(src):
            if token == src:
                continue
            res.add((token, score))
            # Tiger note: the original number is >= 50
            if len(res) >= 500:
                logger.info(f"\033[36m reaches search limit \033[0m")
                break

        # NOTE: src class Completor expects the offset in nr of bytes in the
        # buffer's encoding (Completor.start_column will also be in nr of bytes)
        current_buf_encoding = get_current_buffer_encoding()
        offset = (len(to_bytes(user_src, current_buf_encoding)) -
                  len(to_bytes(src, current_buf_encoding)))

        res = list(res)
        res.sort(key=lambda x: x[1])


        return [
            {
                'word': token,
                'menu': f'[{score},{src}]',
                'offset': offset
            }
            for token, score in res
        ]
