import { getState, setState, subscribe, unsubscribe, resetState } from '../state.js';

describe('state.js', () => {
  afterEach(() => resetState());

  it('deve retornar o estado inicial', () => {
    expect(getState()).toEqual({ blogs: [], prompts: [], selectedBlogIdx: 0 });
  });

  it('deve atualizar o estado', () => {
    setState({ blogs: [{ id: 1 }] });
    expect(getState().blogs).toEqual([{ id: 1 }]);
  });

  it('deve atualizar parcialmente o estado', () => {
    setState({ blogs: [{ id: 1 }] });
    setState({ selectedBlogIdx: 2 });
    expect(getState()).toEqual({ blogs: [{ id: 1 }], prompts: [], selectedBlogIdx: 2 });
  });

  it('deve notificar múltiplos listeners', () => {
    const fn1 = jest.fn();
    const fn2 = jest.fn();
    subscribe(fn1);
    subscribe(fn2);
    setState({ selectedBlogIdx: 2 });
    expect(fn1).toHaveBeenCalledWith(getState());
    expect(fn2).toHaveBeenCalledWith(getState());
    unsubscribe(fn1);
    unsubscribe(fn2);
  });

  it('unsubscribe remove apenas o listener correto', () => {
    const fn1 = jest.fn();
    const fn2 = jest.fn();
    subscribe(fn1);
    subscribe(fn2);
    unsubscribe(fn1);
    setState({ selectedBlogIdx: 1 });
    expect(fn1).not.toHaveBeenCalled();
    expect(fn2).toHaveBeenCalled();
    unsubscribe(fn2);
  });

  it('listeners não são notificados após unsubscribe', () => {
    const fn = jest.fn();
    subscribe(fn);
    unsubscribe(fn);
    setState({ selectedBlogIdx: 1 });
    expect(fn).not.toHaveBeenCalled();
  });

  it('deve resetar o estado', () => {
    setState({ blogs: [{ id: 2 }], selectedBlogIdx: 1 });
    resetState();
    expect(getState()).toEqual({ blogs: [], prompts: [], selectedBlogIdx: 0 });
  });
}); 