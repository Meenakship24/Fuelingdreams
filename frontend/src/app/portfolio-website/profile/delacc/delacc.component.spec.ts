import { ComponentFixture, TestBed } from '@angular/core/testing';

import { DelaccComponent } from './delacc.component';

describe('DelaccComponent', () => {
  let component: DelaccComponent;
  let fixture: ComponentFixture<DelaccComponent>;

  beforeEach(async () => {
    await TestBed.configureTestingModule({
      imports: [DelaccComponent]
    })
    .compileComponents();
    
    fixture = TestBed.createComponent(DelaccComponent);
    component = fixture.componentInstance;
    fixture.detectChanges();
  });

  it('should create', () => {
    expect(component).toBeTruthy();
  });
});
