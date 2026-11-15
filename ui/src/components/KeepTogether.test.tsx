import { render } from '@testing-library/react';
import { describe, expect, it } from 'vitest';
import { KeepTogether } from './KeepTogether';

const kept = (el: HTMLElement) => [...el.querySelectorAll('.whitespace-nowrap')].map((e) => e.textContent);

describe('KeepTogether', () => {
  it('keeps each occurrence of a word on one line', () => {
    const { container } = render(<KeepTogether text="Asks download.db-ip.com, then download.db-ip.com." word="download.db-ip.com" />);
    expect(container.textContent).toBe('Asks download.db-ip.com, then download.db-ip.com.');
    expect(kept(container)).toEqual(['download.db-ip.com', 'download.db-ip.com']);
  });

  it('keeps several words, the longest first, special characters included', () => {
    const { container } = render(
      <KeepTogether text="From github.com and objects.githubusercontent.com (a+b)." word={['github.com', 'objects.githubusercontent.com', '(a+b)']} />,
    );
    expect(container.textContent).toBe('From github.com and objects.githubusercontent.com (a+b).');
    expect(kept(container)).toEqual(['github.com', 'objects.githubusercontent.com', '(a+b)']);
  });

  it('leaves a text without the words, or without words, as is', () => {
    expect(kept(render(<KeepTogether text="Nothing here" word="x.example" />).container)).toEqual([]);
    expect(render(<KeepTogether text="Plain" word={[]} />).container.textContent).toBe('Plain');
  });
});
